#!/usr/bin/env python
# Keep your system clean!
# A command line script that iterates over the currently running jobs and stops them as well as logs the user,
# when a file in the JWD matches to a list of hashes

import argparse
import datetime
import hashlib
import os
import pathlib
import requests
import sys
import time
import zlib

import galaxy_jwd
import yaml
from tqdm import tqdm

CHECKSUM_FILE_ENV = "MALWARE_LIB"

CURRENT_TIME = int(time.time())


def convert_arg_to_byte(mb: str) -> int:
    return int(mb) << 20


def convert_arg_to_seconds(hours: str) -> int:
    return int(hours) * 60 * 60


class Severity:
    def __init__(self, number: int, name: str):
        self.value = number
        self.name = name

    def __eq__(self, other) -> bool:
        if not isinstance(other, Severity):
            raise ValueError("The other must be an instance of the Severity")
        if self.value == other.value and self.name == other.name:
            return True
        else:
            return False

    def __le__(self, other) -> bool:
        if not isinstance(other, Severity):
            raise ValueError("The other must be an instance of the Severity")
        if self.value <= other.value:
            return True
        else:
            return False

    def __ge__(self, other) -> bool:
        if not isinstance(other, Severity):
            raise ValueError("The other must be an instance of the Severity")
        if self.value >= other.value:
            return True
        else:
            return False


VALID_SEVERITIES = (Severity(0, "low"), Severity(1, "medium"), Severity(2, "high"))


def convert_str_to_severity(test_level: str) -> Severity:
    for level in VALID_SEVERITIES:
        if (level.name.casefold()).__eq__(test_level.casefold()):
            return level


def make_parser() -> argparse.ArgumentParser:
    my_parser = argparse.ArgumentParser(
        prog="WALL·E",
        description="""
            Loads a yaml malware library with CRC32 and SHA1 hashes as arguments
            from the environment variable "MALWARE_LIB",
            searches in JWDs of currently running jobs for matching files
            and reports jobs, users and malware details if specified.
            Malware library file has the following schema:
                class:
                    program:
                        version:
                            severity: [high, medium, low]
                            description: "optional info"
                            checksums:
                                crc32: <checksum crc32, gzip algorithm, integer representation>
                                sha1: <checksum sha1, hex representation>
            WARNING:
            Be careful with how you generate the CRC32 hashes:
            There are multiple algorithms, this script is using
            the one specified by RFC in the GZIP specification.
            You should get this when using the gzip command on POSIX systems
            and convert it to integer representation.
            e.g. with:
            gzip -1 -c /path/to/file | tail -c8 | hexdump -n4 -e '"%u"'
            
            The following ENVs (same as gxadmin's) should be set:
                GALAXY_CONFIG_FILE: Path to the galaxy.yml file
                GALAXY_LOG_DIR: Path to the Galaxy log directory
                PGDATABASE: Name of the Galaxy database
                PGUSER: Galaxy database user
                PGHOST: Galaxy database host

                PGPASSFILE: path to .pgpass file (same as gxadmin's) in format:
                <pg_host>:5432:*:<pg_user>:<pg_password>
            The '--delete-user' flag requires additional environment variables:
                GALAXY_BASE_URL: Instance hostname including scheme (https://examplegalaxy.org)
                GALAXY_API_KEY: Galaxy API key with admin privileges
                GALAXY_ROOT: Galaxy root directiory (e.g. /srv/galaxy)
            """,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Could be added to override env
    # my_parser.add_argument(
    #     "malware-library",
    #     help="Path to a malware library",
    #     nargs="+",
    #     type=argparse.FileType("r"),
    # )

    my_parser.add_argument(
        "--chunksize",
        help="Chunksize in MiB for hashing the files in JWDs, defaults to 100 MiB",
        type=convert_arg_to_byte,
        default=100,
    )

    # not yet implemented
    #  my_parser.add_argument(
    #      "--remove-jobs",
    #      action="store_true",
    #      help="Removes the jobs from condor and fails them in Galaxy",
    #  )

    my_parser.add_argument(
        "--min-size",
        metavar="MIN_SIZE_MB",
        help="Minimum filesize im MB to limit the files to scan.",
        type=convert_arg_to_byte,
    )

    my_parser.add_argument(
        "--max-size",
        metavar="MAX_SIZE_MB",
        help="Maximum filesize im MB to limit the files to scan. \
            CAUTION: Not setting this value can lead to very long computation times",
        type=convert_arg_to_byte,
    )

    my_parser.add_argument(
        "--since",
        help="Access time in hours backwards from now",
        type=convert_arg_to_seconds,
    )

    my_parser.add_argument(
        "--tool",
        help="A string to filter tools in the tool_id column of currently running jobs. \
            Use like 'grep' after the gxadmin query queue-details command.",
        type=str,
        default="",
    )
    my_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Report not only the job and user ID that matched, but also Path of matched file and malware info. \
            If set, the scanning process will quit after the first match in a JWD to save resources.",
    )
    my_parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Show progress bar. Leave unset for cleaner logs and slightly higher performance",
    )
    my_parser.add_argument(
        "--delete-user",
        metavar="MIN_SEVERITY",
        choices=VALID_SEVERITIES,
        type=convert_str_to_severity,
        help="Delete user when severity level is equal or higher. \
            Following additional environment variables are expected: \
            GALAXY_API_KEY \
            GALAXY_BASE_URL",
    )
    return my_parser


class Job:
    def __init__(
        self,
        user_id: int,
        user_name: str,
        user_mail: str,
        tool_id: str,
        galaxy_id: int,
        runner_id: int,
        runner_name: str,
        object_store_id: int,
        jwd=None,
    ) -> None:
        self.user_id = user_id
        self.user_name = user_name
        self.user_mail = user_mail
        self.tool_id = tool_id
        self.galaxy_id = galaxy_id
        self.runner_id = runner_id
        self.runner_name = runner_name
        self.object_store_id = object_store_id
        self.jwd = jwd

    def report_id_and_user_name(self) -> str:
        return f"{self.galaxy_id} {self.user_name}"


class Malware:
    """
    Loads a yaml with the following schema
        ---
        class:
          name:
            version:
              severity: [high, medium, low]
              description: "optional info"
              checksums:
                crc32: <checksum crc32>
                sha1: <checksum sha1>
    Can also hold a path to a matched file
    """

    def __init__(
        self,
        malware_class: str,
        program: str,
        version: str,
        severity: Severity,
        description: str,
        crc32: str,
        sha1: str,
    ) -> None:
        self.malware_class = malware_class
        self.program = program
        self.version = version
        self.severity = severity
        self.description = description
        self.crc32 = crc32
        self.sha1 = sha1


def file_accessed_in_range(
    file_stat: os.stat_result, since: int, now=CURRENT_TIME
) -> bool:
    if since is not None:
        if now - since > file_stat.st_atime:
            return False
    return True


def file_in_size_range(file_stat: os.stat_result, min_size=None, max_size=None) -> bool:
    if min_size is not None:
        if file_stat.st_size < min_size:
            return False
    if max_size is not None:
        if file_stat.st_size > max_size:
            return False
    return True


def all_files_in_dir(dir: pathlib.Path, args) -> list[pathlib.Path]:
    """
    Gets all files of given directory and its subdirectories and
    appends file to a list of pathlib.Path objects, if atime
    and the filesize is within the specified range.
    """
    files = []
    for root, _, filenames in os.walk(dir):
        for filename in filenames:
            file = pathlib.Path(os.path.join(root, filename))
            file_stat = file.stat()
            if file_in_size_range(
                file_stat, args.min_size, args.max_size
            ) and file_accessed_in_range(file_stat, args.since):
                files.append(file)
    return files


def load_malware_lib_from_env(malware_file: pathlib.Path) -> dict:
    with open(malware_file, "r") as malware_yaml:
        malware_lib = yaml.safe_load(malware_yaml)
    return malware_lib


def digest_file_crc32(chunksize: int, path: pathlib.Path) -> int:
    crc32 = 0
    with open(path, "rb") as specimen:
        while chunk := specimen.read(chunksize):
            crc32 = zlib.crc32(chunk, crc32)
    return crc32


def digest_file_sha1(chunksize: int, path: pathlib.Path) -> str:
    sha1 = hashlib.sha1()
    with open(path, "rb") as specimen:
        while chunk := specimen.read(chunksize):
            sha1.update(chunk)
    return sha1.hexdigest()


def scan_file_for_malware(
    chunksize: int, file: pathlib.Path, lib: list[Malware]
) -> list[Malware]:
    """
    Returning a list of Malware, because
    it could potentially happen (even if it should not),
    that the same signature was added to the library more than once
    under different names or, extrem unlikely,
    a hash collision occurs.
    Args:
        chunksize: Chunksize in bytes
        file: pathlib.Path to the file to be checked
        lib: a list ob Malware objects with CRC32 and SHA-1 sums
    Returns:
        A list of Malware objects with matching CRC32 AND SHA-1 sums
    """
    matches = []
    crc32 = digest_file_crc32(chunksize, file)
    sha1 = None
    for malware in lib:
        if malware.crc32 == crc32:
            if sha1 is None:
                sha1 = digest_file_sha1(chunksize, file)
            if malware.sha1 == sha1:
                matches.append(malware)
    return matches


def report_matching_malware(job: Job, malware: Malware, path: pathlib.Path) -> str:
    """
    Create log line depending on verbosity
    """
    return f"{datetime.datetime.now()} {job.user_id} {job.user_name} {job.user_mail} \
{job.tool_id} {job.galaxy_id} {job.runner_id} {job.runner_name} {job.object_store_id} \
{malware.malware_class} {malware.program} {malware.severity.name} {malware.version} {path}"


def construct_malware_list(malware_yaml: dict) -> list[Malware]:
    """
    creates a flat list of malware objects, that hold all info
    The nested structure in yaml is for better optical structuring
    """
    malware_list = []
    for malware_class in malware_yaml:
        for program in malware_yaml[malware_class]:
            for version in malware_yaml[malware_class][program]:
                malware_list.append(
                    Malware(
                        malware_class=malware_class,
                        program=program,
                        version=version,
                        severity=convert_str_to_severity(
                            malware_yaml[malware_class][program][version]["severity"]
                        ),
                        description=malware_yaml[malware_class][program][version][
                            "description"
                        ],
                        crc32=malware_yaml[malware_class][program][version][
                            "checksums"
                        ]["crc32"],
                        sha1=malware_yaml[malware_class][program][version]["checksums"][
                            "sha1"
                        ],
                    )
                )
    return malware_list


class JWDGetter:
    """
    This class is a workaround for calling 'galaxy_jwd.py's main function.
    """

    def __init__(
        self, galaxy_config_file: pathlib.Path, pulsar_app_conf: pathlib.Path
    ) -> None:
        """
        Reads the storage backend configuration
        (might deserve it's own function in galaxy_jwd.py)
        """
        object_store_conf = galaxy_jwd.get_object_store_conf_path(galaxy_config_file)
        backends = galaxy_jwd.parse_object_store(object_store_conf)
        # Add pulsar staging directory (runner: pulsar_embedded) to backends
        backends["pulsar_embedded"] = galaxy_jwd.get_pulsar_staging_dir(pulsar_app_conf)
        self.backends = backends

    # might deserve it's own function in galaxy_jwd.py
    def get_jwd_path(self, job: Job):
        jwd = galaxy_jwd.decode_path(
            job.galaxy_id,
            [job.object_store_id],
            self.backends,
            job.runner_name,
        )
        return jwd


class RunningJobDatabase(galaxy_jwd.Database):
    def __init__(self, db_host: str, db_name: str, db_user: str, db_password: str):
        super().__init__(
            db_name,
            db_user,
            db_host,
            db_password,
        )

    def get_running_jobs(self, tool=None) -> list[Job]:
        query = f"""
                SELECT j.user_id, u.username, u.email, j.tool_id, j.id,
                j.job_runner_external_id, j.job_runner_name, j.object_store_id
                FROM
                    job j
                    INNER JOIN galaxy_user u ON j.user_id = u.id
                WHERE state = 'running'
                AND object_store_id IS NOT NULL
                AND user_id IS NOT NULL
            """
        cur = self.conn.cursor()
        if len(tool) > 0:
            query += f"AND tool_id LIKE '%{tool}%'"
        cur.execute(query + ";")
        running_jobs = cur.fetchall()
        cur.close()
        self.conn.close()
        # Create a dictionary with job_id as key and object_store_id, and
        # update_time as values
        if not running_jobs:
            print(
                f"No running jobs with tool_id like {tool} found.",
                file=sys.stderr,
            )
            sys.exit(1)
        running_jobs_list = []
        for (
            user_id,
            user_name,
            user_mail,
            tool_id,
            job_id,
            runner_id,
            runner_name,
            object_store_id,
        ) in running_jobs:
            running_jobs_list.append(
                Job(
                    user_id=user_id,
                    user_name=user_name,
                    user_mail=user_mail,
                    tool_id=tool_id,
                    galaxy_id=job_id,
                    runner_id=runner_id,
                    runner_name=runner_name,
                    object_store_id=object_store_id,
                )
            )
        return running_jobs_list


def get_path_from_env_or_error(env: str) -> pathlib.Path:
    if os.environ.get(env):
        if (path := pathlib.Path(os.environ.get(env).strip())).exists():
            return path
        else:
            raise ValueError(f"Path for {env} is invalid")
    else:
        raise ValueError(f"Please set ENV {env}")


def get_str_from_env_or_error(env: str) -> str:
    if os.environ.get(env):
        if len(from_env := os.environ.get(env).strip()) > 0:
            return from_env
        else:
            raise ValueError(f"Path for {env} is invalid")
    else:
        raise ValueError(f"Please set ENV {env}")


def delete_user(user_id: int, base_url: str, api_key: str) -> bool:
    url = f"{base_url}/api/users/{encode_galaxy_user_id(user_id)}"
    header = {"x-api-key": api_key}
    response = requests.delete(url=url, headers=header)
    if response.status_code == 200:
        print(f"User {user_id} deleted successfully.")
    else:
        print(f"Failed to delete user {user_id}!")


def encode_galaxy_user_id(id: int) -> str:
    pass


def main():
    """
    Miner Finder's main function. Shows a status bar while processing the jobs found in Galaxy
    """
    args = make_parser().parse_args()
    galaxy_config_file = get_path_from_env_or_error("GALAXY_CONFIG_FILE")

    jwd_getter = JWDGetter(
        galaxy_config_file=galaxy_config_file,
        pulsar_app_conf=get_path_from_env_or_error("GALAXY_PULSAR_APP_CONF"),
    )
    db = RunningJobDatabase(
        db_host=get_str_from_env_or_error("PGHOST"),
        db_password=galaxy_jwd.extract_password_from_pgpass(
            get_path_from_env_or_error("PGPASSFILE")
        ),
        db_name=get_str_from_env_or_error("PGDATABASE"),
        db_user=get_str_from_env_or_error("PGUSER"),
    )
    malware_library = construct_malware_list(
        malware_yaml=load_malware_lib_from_env(
            malware_file=get_path_from_env_or_error("MALWARE_LIB")
        )
    )
    jobs = db.get_running_jobs(args.tool)
    if args.delete_user:
        api_key = get_str_from_env_or_error("GALAXY_API_KEY")
        galaxy_url = get_path_from_env_or_error("GALAXY_BASE_URL")
        galaxy_root = get_path_from_env_or_error("GALAXY_ROOT")
    if args.interactive:
        if args.verbose:
            print(
                "TIMESTAMP GALAXY_USER_ID GALAXY_USER_MAIL TOOL_ID \
                GALAXY_JOB_ID RUNNER_JOB_ID RUNNER_NAME MALWARE_CLASS \
                OBJECT_STORE_ID MALWARE SEVERITY MALWARE_VERSION PATH"
            )
        else:
            print("GALAXY_USER JOB_ID")
    for job in tqdm(
        jobs,
        disable=(not args.interactive),
        desc="Processing jobs…",
        ascii=False,
        ncols=75,
    ):
        jwd_path = jwd_getter.get_jwd_path(job)
        if pathlib.Path(jwd_path).exists():
            job.jwd = pathlib.Path(jwd_path)
            for file in all_files_in_dir(job.jwd, args):
                matching_malware = scan_file_for_malware(
                    chunksize=args.chunksize, file=file, lib=malware_library
                )
                if len(matching_malware) > 0:
                    print("\n")
                    for malware in matching_malware:
                        if args.verbose:
                            print(
                                report_matching_malware(
                                    job=job,
                                    malware=malware,
                                    path=file,
                                )
                            )
                        if args.delete_user:
                            print(type(args.delete_user))
                            print(type(malware.severity))
                            if args.delete_user <= malware.severity:
                                delete_user(
                                    user_id=job.user_id,
                                    api_key=api_key,
                                    base_url=galaxy_url,
                                )

                    else:
                        print(job.report_id_and_user_name())
                        break

        else:
            print(
                f"JWD for Job {job.galaxy_id} found but does not exist in FS",
                file=sys.stderr,
            )
    if args.interactive:
        print("Complete.")


if __name__ == "__main__":
    main()

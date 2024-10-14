#!/usr/bin/env python

"""Keep your system clean!

A command line script that iterates over the currently running jobs and stops
them as well as logs the user, when a file in the JWD matches to a list of
hashes.
"""

import argparse
import hashlib
import logging
import os
import pathlib
import subprocess
import sys
import time
import zlib
from typing import Dict, List

import galaxy_jwd
import requests
import yaml

CHECKSUM_FILE_ENV = "MALWARE_LIB"

DEFAULT_SUBJECT = "Galaxy Account deleted due to ToS violations"
DEFAULT_MESSAGE = """
Our systems have detected activity related to your Galaxy account that most likely violate our terms of service.
To prevent damage and in accordance with our terms of service, we automatically deleted your account.
This means your jobs were terminated and you can not login anymore.
However it is possible to restore the account and its data.
If you think your account was deleted due to an error, please contact
"""
ONLY_ONE_INSTANCE = "The other must be an instance of the Severity class"

UserId = str
UserMail = str
UserIdMail = Dict[UserId, UserMail]

logging.basicConfig(
    format="{asctime} - {levelname} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M",
)
logger = logging.getLogger(__name__)
GXADMIN_PATH = os.getenv('GXADMIN_PATH', '/usr/local/bin/gxadmin')


def convert_arg_to_byte(mb: str) -> int:
    return int(mb) << 20


def convert_arg_to_seconds(hours: str) -> float:
    return float(hours) * 60 * 60


class Severity:
    def __init__(self, number: int, name: str):
        self.value = number
        self.name = name

    def __eq__(self, other) -> bool:
        if not isinstance(other, Severity):
            raise ValueError(ONLY_ONE_INSTANCE)
        if self.value == other.value and self.name == other.name:
            return True
        else:
            return False

    def __le__(self, other) -> bool:
        if not isinstance(other, Severity):
            raise ValueError(ONLY_ONE_INSTANCE)
        if self.value <= other.value:
            return True
        else:
            return False

    def __ge__(self, other) -> bool:
        if not isinstance(other, Severity):
            raise ValueError(ONLY_ONE_INSTANCE)
        if self.value >= other.value:
            return True
        else:
            return False


VALID_SEVERITIES = (Severity(0, "LOW"), Severity(1, "MEDIUM"), Severity(2, "HIGH"))


def convert_str_to_severity(test_level: str) -> Severity:
    for level in VALID_SEVERITIES:
        if (level.name.casefold()).__eq__(test_level.casefold()):
            return level
    raise ValueError("{test_level} is not a valid severity level")


def make_parser() -> argparse.ArgumentParser:
    my_parser = argparse.ArgumentParser(
        prog="WALL·E",
        description="""
            Galaxy's Static Malware Scanner

            DESCRIPTION
            Loads a yaml malware library with CRC32 and SHA1 hashes
            from the environment variable "MALWARE_LIB".
            Gets a list of running jobs from Galaxy's database,
            optionally filtered by a '--tool <str>' substring.
            Then iterates over the jobs, scans all files in the Job Working Directory,
            optionally filtered by size and access time,
            for files that match both hashes and reports details to stdout.
            If '--delete-user' flag is set it notifies and deletes the user.

            REQUIREMENTS
            galaxy_jwd.py as well as all other imported packages must be present.
            The following environment variables (same as gxadmin's) should be set:
                GALAXY_CONFIG_FILE: Path to the galaxy.yml file
                PGDATABASE: Name of the Galaxy database
                PGUSER: Galaxy database user
                PGHOST: Galaxy database host
                PGPASSFILE: path to .pgpass file (same as gxadmin's) in format:
                <pg_host>:5432:*:<pg_user>:<pg_password>

            MALWARE LIBRARY SCHEMA
            The malware library file has the following schema:
                class:
                    program:
                        version:
                            severity: [high, medium, low]
                            description: "optional info"
                            checksums:
                                crc32: <checksum crc32, gzip algorithm, integer representation>
                                sha1: <checksum sha1, hex representation>
            WARNING:
            ----------------------------------------------------------------
            Be careful with how you generate the CRC32 hashes:
            There are multiple algorithms, this script is using
            the one specified by RFC in the GZIP specification.
            You should get this when using the gzip command on POSIX systems
            and convert it to integer representation.
            e.g. with:
            gzip -1 -c /path/to/file | tail -c8 | hexdump -n4 -e '"%u"'
            ----------------------------------------------------------------
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

    my_parser.add_argument(
        "--kill",
        action="store_true",
        help="Kill malicious jobs with gxadmin.",
    )

    my_parser.add_argument(
        "--min-size",
        metavar="MIN_SIZE_MB",
        help="Minimum filesize im MB to limit the files to scan. \
The check will be skipped if value is 0 (default)",
        type=convert_arg_to_byte,
        default=0,
    )

    my_parser.add_argument(
        "--max-size",
        metavar="MAX_SIZE_MB",
        help="Maximum filesize im MB to limit the files to scan.\n \
CAUTION: Not setting this value can lead to very long computation times.\n \
The check will be skipped if value is 0 (default)",
        type=convert_arg_to_byte,
        default=0,
    )

    my_parser.add_argument(
        "--since",
        help="Access time in hours backwards from now, default=0 (skip check)",
        type=convert_arg_to_seconds,
        default=0,
    )

    my_parser.add_argument(
        "--tool",
        help="A string to filter tools in the tool_id column of currently running jobs.\n \
Use like 'grep' after the gxadmin query queue-details command.",
        type=str,
        default="",
    )
    my_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Report details for every match."
    )
    my_parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Emit additional log messages for debugging Wall-E.",
    )
    my_parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Show table header.",
    )
    my_parser.add_argument(
        "--delete-user",
        metavar="MIN_SEVERITY",
        choices=VALID_SEVERITIES,
        type=convert_str_to_severity,
        help="Delete user when the found malware's severity level is equal or higher than this value.\n \
Possible values are 'LOW', 'MEDIUM' or 'HIGH'.\n \
This feature requires Galaxy's notification framework to be enabled.\n \
Make sure that you know the consequences on your instance, especially regarding GDPR and\n \
what happens when a user is set to deleted (e.g. when a user is purged automatically after deletion).\n \
Following additional environment variables are expected:\n \
GALAXY_BASE_URL: Instance hostname including scheme (https://examplegalaxy.org)\n \
GALAXY_API_KEY: Galaxy API key with admin privileges\n \
Optional, for default see documentation:\n \
WALLE_USER_DELETION_MESSAGE: Message that tells the user why their account is deleted.\n \
WALLE_USER_DELETION_SUBJECT: The message's subject line.",
    )
    return my_parser


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


class Job:
    def __init__(
        self,
        user_id: UserId,
        user_name: str,
        user_mail: UserMail,
        tool_id: str,
        galaxy_id: int,
        runner_id: int,
        runner_name: str,
        object_store_id: int,
        jwd=pathlib.Path(),
        files=[],
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
        self.files = files

    def set_jwd_path(self, jwd: str) -> bool:
        jwd_path = pathlib.Path(jwd)
        if jwd_path.exists():  # Move to job initialization
            self.jwd = jwd_path
            return True
        else:
            return False

    def check_if_jwd_exists_and_get_files(self, args: argparse.Namespace) -> bool:
        """
        Gets all files of given directory and its subdirectories and
        appends file to a list of pathlib.Path objects, if atime
        and the filesize is within the specified range.
        """
        if self.jwd.exists():
            for dirpath, _, filenames in os.walk(self.jwd):
                self.collect_files_in_a_directory(
                    args=args, dirpath=dirpath, filenames=filenames
                )
            if len(self.files) > 0:
                return True
        return False

    def collect_files_in_a_directory(
        self, args: argparse.Namespace, dirpath: str, filenames: List[str]
    ):
        for filename in filenames:
            file = pathlib.Path(os.path.join(dirpath, filename))
            if not os.path.islink(file):
                self.check_if_file_in_range_and_accessed(args=args, filepath=file)

    def check_if_file_in_range_and_accessed(
        self, filepath: pathlib.Path, args: argparse.Namespace
    ):
        try:
            file_stat = filepath.stat()
            if file_in_size_range(
                file_stat, args.min_size, args.max_size
            ) and file_accessed_in_range(file_stat, args.since):
                self.files.append(filepath)
        except OSError:
            pass


class Case:
    def __init__(
        self,
        verbose: bool,
        job: Job,
        malware: Malware,
        fileindex: int,
        reported_users: UserIdMail,
        delete_users: UserIdMail,
    ) -> None:
        self.job = job
        self.verbose = verbose
        self.malware = malware
        self.fileindex = fileindex
        self.reported_users = reported_users
        self.delete_users = delete_users

    def report_according_to_verbosity(self) -> UserIdMail:
        if self.verbose:
            self.report_matching_malware()
            return {}
        elif self.job.user_id not in self.reported_users:
            return self.report_id_and_user_name()
        else:
            return {}

    def mark_user_for_deletion(self, severity: Severity) -> UserIdMail:
        if self.job.user_id not in self.delete_users:
            return self.check_severity_level(severity)
        return {}

    def check_severity_level(self, severity: Severity) -> UserIdMail:
        if self.malware.severity >= severity:
            logger.debug(f"User %s marked for deletion", self.job.user_id)
            return {self.job.user_id: self.job.user_mail}
        else:
            return {}

    def report_id_and_user_name(self) -> UserIdMail:
        logger.info("%s %s", self.job.user_id, self.job.user_name)
        return {self.job.user_id: self.job.user_mail}

    def report_matching_malware(self):
        """
        Create log line depending on verbosity
        """
        logger.debug(
            "%s %s %s %s %s %s %s %s %s %s %s %s %s",
            self.malware.severity.name,
            self.job.user_id,
            self.job.user_name,
            self.job.user_mail,
            self.job.tool_id,
            self.job.galaxy_id,
            self.job.runner_id,
            self.job.runner_name,
            self.job.object_store_id,
            self.malware.malware_class,
            self.malware.program,
            self.malware.version,
            self.job.files[self.fileindex],
        )


def file_accessed_in_range(
    file_stat: os.stat_result, since: float, now=time.time()
) -> bool:
    if since != 0 and now - since > file_stat.st_atime:
        return False
    return True


def file_in_size_range(file_stat: os.stat_result, min_size: int, max_size: int) -> bool:
    if min_size is not None and file_stat.st_size < min_size:
        return False
    if max_size is not None and file_stat.st_size > max_size:
        return False
    return True


def load_malware_lib_from_env(malware_file: pathlib.Path) -> dict:
    with open(malware_file, "r") as malware_yaml:
        malware_lib = yaml.safe_load(malware_yaml)
    return malware_lib


def digest_file_crc32(chunksize: int, path: pathlib.Path) -> int:
    crc32 = 0
    try:
        with open(path, "rb") as specimen:
            while chunk := specimen.read(chunksize):
                crc32 = zlib.crc32(chunk, crc32)
    except PermissionError:
        logger.warning(f"Permission denied for file: {path}")
    return crc32


def digest_file_sha1(chunksize: int, path: pathlib.Path) -> str:
    sha1 = hashlib.sha1()
    try:
        with open(path, "rb") as specimen:
            while chunk := specimen.read(chunksize):
                sha1.update(chunk)
    except PermissionError:
        logger.warning(f"Permission denied for file: {path}")
    return sha1.hexdigest()


def scan_file_for_malware(
    chunksize: int, file: pathlib.Path, lib: List[Malware]
) -> List[Malware]:
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
    logger.debug(f"File {file} calculated CRC32: {crc32}")
    sha1 = None
    for malware in lib:
        if malware.crc32 == crc32:
            logger.debug(
                f"File {file} CRC32 matches {malware.program} {malware.version}"
            )
            if sha1 is None:
                sha1 = digest_file_sha1(chunksize, file)
            if malware.sha1 == sha1:
                matches.append(malware)
            else:
                logger.debug(
                    f"File {file} SHA1 does not match {malware.program} {malware.version}"
                )
    return matches


def construct_malware_list(malware_yaml: dict) -> [Malware]:
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
    def get_jwd_path(self, job: Job) -> str:
        jwd = galaxy_jwd.decode_path(
            job.galaxy_id,
            [job.object_store_id],
            self.backends,
            job.runner_name,
        )
        return jwd


class RunningJobDatabase(galaxy_jwd.Database):
    def __init__(self, db_name: str, db_host=None, db_user=None, db_password=None):
        super().__init__(
            db_name,
            db_user,
            db_host,
            db_password,
        )

    def get_running_jobs(self, tool: str) -> List[Job]:
        query = """
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
        if tool is not None and len(tool) > 0:
            query += f"AND tool_id LIKE '%{tool}%'"
        cur.execute(query + ";")
        running_jobs = cur.fetchall()
        cur.close()
        self.conn.close()
        # Create a dictionary with job_id as key and object_store_id, and
        # update_time as values
        if running_jobs:
            logger.debug(f"Found {len(running_jobs)} running jobs matching '{tool}'")
        else:
            logger.debug(
                f"No running jobs with tool_id like {tool} found.")
            sys.exit(0)
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


def kill_job(job: Job):
    """Attempt to kill a job by its galaxy_id using gxadmin."""
    logger.info(f"Failing malicious job: {job.galaxy_id}")
    serial_args = [
        [
            GXADMIN_PATH,
            "mutate",
            "fail-job",
            str(job.galaxy_id),
            "--commit",
        ],
        [
            GXADMIN_PATH,
            "mutate",
            "fail-terminal-datasets",
            "--commit",
        ],
    ]
    for args in serial_args:
        logger.debug(f"COMMAND: {' '.join(args)}")
        try:
            result = subprocess.run(args, check=True, capture_output=True, text=True)
            if result.stdout:
                logger.debug(f"COMMAND STDOUT:\n{result.stdout}")
            if result.stderr:
                logger.debug(f"COMMAND STDERR:\n{result.stderr}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error failing job {job.galaxy_id}:\n{e}")


def evaluate_match_for_deletion(
    job: Job,
    match: Malware,
    delete_users: UserIdMail,
    severity: Severity,
) -> UserIdMail:
    """
    Miner Finder's main function. Shows a status bar while processing the jobs
    found in Galaxy.
    If in verbose mode, print detailed information for every match. No updates
    on 'reported' needed.
    """
    if job.user_id not in delete_users and (severity <= match.severity):
        return {job.user_id: job.user_mail}
    return {}


def get_path_from_env_or_error(env: str) -> pathlib.Path:
    try:
        os.environ.get(env)
        try:
            (path := pathlib.Path(os.environ.get(env, "").strip())).exists()
            return path
        except ValueError:
            logger.error(f"Path for %s is invalid", env)
            raise ValueError
    except ValueError:
        logger.error(f"Please set ENV %s", env)
        raise ValueError


def get_str_from_env_or_error(env: str) -> str:
    try:
        os.environ.get(env)
        try:
            if len(from_env := os.environ.get(env, "").strip()) == 0:
                raise ValueError
            else:
                return from_env
        except ValueError:
            logger.error(f"Path for %s is invalid", env)
            raise ValueError
    except ValueError:
        logger.error(f"Please set ENV %s", env)
        raise ValueError


class GalaxyAPI:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        delete_subject: str,
        delete_message: str,
    ) -> None:
        self.base_url = base_url
        self.api_key = api_key
        self.auth_header = {"x-api-key": self.api_key}
        self.delete_subject = delete_subject
        self.delete_message = delete_message

    def notify_user(self, encoded_user_id: UserId) -> bool:
        url = f"{self.base_url}/api/notifications"
        response = requests.post(
            url=url,
            headers=self.auth_header,
            json={
                "recipients": {
                    "user_ids": [encoded_user_id],
                    "group_ids": [],
                    "role_ids": [],
                },
                "notification": {
                    "source": "string",
                    "category": "message",
                    "variant": "urgent",
                    "content": {
                        "subject": self.delete_subject,
                        "message": self.delete_message,
                        "category": "message",
                    },
                },
            },
        )
        if response.status_code == 200:
            if response.json()["total_notifications_sent"] == 1:
                return True
        logger.error(
            "Can not notify user %s, response from Galaxy: %s",
            encoded_user_id,
            response.content,
        )
        return False

    def delete_user(self, encoded_user_id: UserId) -> bool:
        url = f"{self.base_url}/api/users/{encoded_user_id}"
        response = requests.delete(url=url, headers=self.auth_header)
        if response.status_code != 200:
            logger.error(
                "Can not encode delete user %s, response from Galaxy: %s",
                encoded_user_id,
                response.content,
            )
            return False
        else:
            return True

    def encode_galaxy_user_id(self, decoded_id: UserId) -> str:
        url = f"{self.base_url}/api/configuration/encode/{decoded_id}"
        response = requests.get(url=url, headers=self.auth_header)
        if response.status_code != 200:
            logger.error(
                "Can not encode user id, response from Galaxy: %s", response.content
            )
            return ""
        else:
            json_response = response.json()
            return json_response["encoded_id"]

    def encode_id_notify_and_delete_user(self, user_id: UserId):
        encoded_user_id = self.encode_galaxy_user_id(decoded_id=user_id)
        if self.notify_user(encoded_user_id):
            logger.debug("User %s notified.", user_id)
            if self.delete_user(encoded_user_id):
                logger.info("User %s notified and deleted.", user_id)


def print_table_header(verbose: bool, interactive: bool):
    if interactive:
        if verbose:
            logger.debug(
                "MALWARE_SEVERITY USER_ID USER_NAME USER_MAIL TOOL_ID GALAXY_JOB_ID \
RUNNER_JOB_ID RUNNER_NAME OBJECT_STORE_ID MALWARE_CLASS MALWARE_NAME MALWARE_VERSION PATH"
            )
        else:
            logger.info("GALAXY_USER JOB_ID")


def get_database_with_password() -> RunningJobDatabase:
    return RunningJobDatabase(
        db_host=get_str_from_env_or_error("PGHOST"),
        db_password=galaxy_jwd.extract_password_from_pgpass(
            get_path_from_env_or_error("PGPASSFILE")
        ),
        db_name=get_str_from_env_or_error("PGDATABASE"),
        db_user=get_str_from_env_or_error("PGUSER"),
    )


def main():
    args = make_parser().parse_args()
    logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    jwd_getter = JWDGetter(
        galaxy_config_file=get_path_from_env_or_error("GALAXY_CONFIG_FILE"),
        pulsar_app_conf=get_path_from_env_or_error("GALAXY_PULSAR_APP_CONF"),
    )
    db = get_database_with_password()
    malware_library = construct_malware_list(
        malware_yaml=load_malware_lib_from_env(
            malware_file=get_path_from_env_or_error("MALWARE_LIB")
        )
    )
    jobs = db.get_running_jobs(args.tool)
    delete_users = dict()
    reported_users: UserIdMail = {}

    print_table_header(verbose=args.verbose, interactive=args.interactive)
    for job in jobs:
        if not job.set_jwd_path(jwd_getter.get_jwd_path(job)):
            continue
        if not job.check_if_jwd_exists_and_get_files(args):
            continue
        for index, file in enumerate(job.files):
            matching_malware = scan_file_for_malware(
                chunksize=args.chunksize, file=file, lib=malware_library
            )
            for malware in matching_malware:
                case = Case(
                    job=job,
                    verbose=args.verbose,
                    malware=malware,
                    fileindex=index,
                    reported_users=reported_users,
                    delete_users=delete_users,
                )
                reported_users.update(case.report_according_to_verbosity())
                if args.delete_user:
                    delete_users.update(case.mark_user_for_deletion(args.delete_user))
            if matching_malware and args.kill:
                kill_job(job)
    # Deletes users at the end, to report all malicious jobs of a user
    if args.delete_user:
        api = GalaxyAPI(
            api_key=get_str_from_env_or_error("GALAXY_API_KEY"),
            base_url=get_str_from_env_or_error("GALAXY_BASE_URL"),
            delete_subject=os.environ.get(
                "WALLE_USER_DELETION_SUBJECT", DEFAULT_SUBJECT
            ),
            delete_message=os.environ.get(
                "WALLE_USER_DELETION_MESSAGE", DEFAULT_MESSAGE
            ),
        )
        for user_id in delete_users:
            # add notification here
            api.encode_id_notify_and_delete_user(user_id)

    if args.interactive:
        logger.debug("Complete.")


if __name__ == "__main__":
    main()

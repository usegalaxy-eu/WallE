[![Super-Linter](https://github.com/usegalaxy-eu/WallE/actions/workflows/lint.yml/badge.svg)](https://github.com/marketplace/actions/super-linter)

# WALL·E

Keep your Galaxy job working directories (JWDs) clean.

WALL·E is a Python script that iterates over your (toolname filtered) running jobs, calculates checksums for all files in the job working directory (JWD)
and compares them to a community-created [database](https://github.com/usegalaxy-eu/intergalactic-most-wanted-list) of malicious software.
Deployed with Ansible.

If you find new miners or other malicious stuff, please add those signatures to our [`intergalactic-most-wanted-list`](https://github.com/usegalaxy-eu/intergalactic-most-wanted-list).

## Prerequisites
This role expect several requirements.
1. [galaxy_jwd.py](https://github.com/usegalaxy-eu/infrastructure-playbook/blob/master/roles/usegalaxy-eu.bashrc/files/galaxy_jwd.py) must exist in the directory of `walle_script_location`
2. Python 3
2. the python packages imported in `walle.py` and `galaxy_jwd.py` must be present
3. Following environment vars must be set:
    - `GALAXY_CONFIG_FILE`: Path to the galaxy.yml file
    - `PGDATABASE`: Name of the Galaxy database
    - `PGUSER`: Galaxy database user
    - `PGHOST`: Galaxy database host
    - `PGPASSFILE`: path to Postgres' `.pgpass` file (defaults to `/home/<walle_user_name>/.pgpass`)
    - `GALAXY_PULSAR_APP_CONF`: [Galaxy's Pulsar configuration file](https://github.com/galaxyproject/pulsar/blob/master/app.yml.sample) (for the staging directory)[^1]
4. These environment vars must be set when using `--delete-user` mode
    - `GALAXY_BASE_URL`: Instance hostname including scheme (https://examplegalaxy.org)
    - `GALAXY_API_KEY`: Galaxy API key with admin privileges\
    Optional, for default values see the constants in `walle.py`:
    - `WALLE_USER_DELETION_MESSAGE`: Message that tells the user why their account is deleted.
    - `WALLE_USER_DELETION_SUBJECT`: The message's subject line.

[^1]: You should always run 'dangerous' jobs in embedded Pulsar.
## Ansible
For ansible details consult `defaults/main.yml`, it should be pretty much self-explanatory.

## Usage
From the tools help command:
~~~
usage: WALL·E [-h] [--chunksize CHUNKSIZE] [--min-size MIN_SIZE_MB] [--max-size MAX_SIZE_MB] [--since SINCE] [--tool TOOL] [-v] [-i] [--delete-user MIN_SEVERITY]

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


optional arguments:
  -h, --help            show this help message and exit
  --chunksize CHUNKSIZE
                        Chunksize in MiB for hashing the files in JWDs, defaults to 100 MiB
  --min-size MIN_SIZE_MB
                        Minimum filesize im MB to limit the files to scan. The check will be skipped if value is 0 (default)
  --max-size MAX_SIZE_MB
                        Maximum filesize im MB to limit the files to scan.
                         CAUTION: Not setting this value can lead to very long computation times.
                         The check will be skipped if value is 0 (default)
  --since SINCE         Access time in hours backwards from now, default=0 (skip check)
  --tool TOOL           A string to filter tools in the tool_id column of currently running jobs.
                         Use like 'grep' after the gxadmin query queue-details command.
  -v, --verbose         Report details for every match.
  -i, --interactive     Show table header.
  --delete-user MIN_SEVERITY
                        Delete user when the found malware's severity level is equal or higher than this value.
                         Possible values are 'LOW', 'MEDIUM' or 'HIGH'.
                         This feature requires Galaxy's notification framework to be enabled.
                         Make sure that you know the consequences on your instance, especially regarding GDPR and
                         what happens when a user is set to deleted (e.g. when a user is purged automatically after deletion).
                         Following additional environment variables are expected:
                         GALAXY_BASE_URL: Instance hostname including scheme (https://examplegalaxy.org)
                         GALAXY_API_KEY: Galaxy API key with admin privileges
                         Optional, for default see documentation:
                         WALLE_USER_DELETION_MESSAGE: Message that tells the user why their account is deleted.
                         WALLE_USER_DELETION_SUBJECT: The message's subject line.
~~~

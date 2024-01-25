[![Super-Linter](https://github.com/usegalaxy_eu/WallE/actions/workflows/lint/badge.svg)](https://github.com/marketplace/actions/super-linter)

# WALL·E
Keep your Galaxy job working directories (JWDs) clean.  
Python script that fetches (toolname filtered) running jobs, calculates checksums for all files in the jobworking directory and compares them to a database.  
Deployed with Ansible.

## Dependencies
This role expect several requirements.
1. `galaxy_jwd.py` must exist in the directory of `walle_script_location`
2. Python 3
2. the python packages imported in `walle.py` and `galaxy_jwd.py` must be present
3. Following environment vars must be set:
    - `GALAXY_CONFIG_FILE`: Path to the galaxy.yml file
    - `GALAXY_LOG_DIR`: Path to the Galaxy log directory
    - `PGDATABASE`: Name of the Galaxy database
    - `PGUSER`: Galaxy database user
    - `PGHOST`: Galaxy database host
    - `PGPASSFILE`: path to Postgres' `.pgpass` file (defaults to `/home/<walle_user_name>/.pgpass`)
    - `GALAXY_PULSAR_APP_CONF`: 
## Ansible
For ansible details consult `defaults/main.yml`, it should be pretty much self-explanatory.  

## Usage
From the tools help command:
~~~
usage: Wall·E [-h] [--chunksize CHUNKSIZE] [--min-size MIN_SIZE_MB] [--max-size MAX_SIZE_MB] [--since SINCE] [--tool TOOL] [-v] [-i]

            Loads a yaml malware library with CRC32 and SHA1 hashes as arguments
            from the environment variable "MALWARE_LIB",
            searches in JWDs of currently running jobs for matching files
            and reports jobs, users and malware details if specified.
            Malware library file has the following schema:
                class:
                    name:
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

                PGPASSFILE: path to a ~/.pgpass file (same as gxadmin's) in format:
                <pg_host>:5432:*:<pg_user>:<pg_password>
            

optional arguments:
  -h, --help            show this help message and exit
  --chunksize CHUNKSIZE
                        Chunksize in MiB for hashing the files in JWDs, defaults to 100 MiB
  --min-size MIN_SIZE_MB
                        Minimum filesize im MB to limit the files to scan.
  --max-size MAX_SIZE_MB
                        Maximum filesize im MB to limit the files to scan.             CAUTION: Not setting this value can lead to very long computation times
  --since SINCE         Access time in hours backwards from now
  --tool TOOL           A string to filter tools in the tool_id column of currently running jobs.             Use like 'grep' after the gxadmin query queue-details command.
  -v, --verbose         Report not only the job and user ID that matched, but also Path of matched file and malware info.             If set, the scanning process will quit after the first match in a JWD to save resources.
  -i, --interactive     Show progress bar. Leave unset for cleaner logs and slightly higher performance
~~~
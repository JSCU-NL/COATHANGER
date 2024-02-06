#!/usr/bin/env python3
"""
    FortiGate COATHANGER IOC Checker

    https://github.com/JSCU-NL/COATHANGER
    https://www.ncsc.nl/documenten/publicaties/2024/februari/6/mivd-aivd-advisory-coathanger-tlp-clear
"""
import argparse
import logging
import statistics
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

try:
    import structlog
    from dissect.target import Target
    from dissect.target.exceptions import UnsupportedPluginError
    from dissect.target.tools.info import print_target_info
    from flow.record import RecordDescriptor
    from tabulate import tabulate

except ImportError:
    print("Please install dependencies using `pip install -r requirements.txt`")
    exit()

uft = datetime.utcfromtimestamp
logging.getLogger("dissect.target.target").setLevel(logging.ERROR)

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.dev.ConsoleRenderer(),
    ]
)
log = structlog.get_logger()

# Any of the following files are a strong indicator of a COATHANGER infection.
SUSPICIOUS_FILES = [
    # persistent
    "/data2/.*/authd",
    "/data2/.*/httpsd",
    "/data2/.*/newcli",
    "/data2/.*/preload.so",
    "/data2/.*/sh",
    # possibly volatile
    "/data/etc/ld.so.preload",
    "/etc/ld.so.preload",
    "/lib/liblog.so",
    "/tmp/libpe.so",
    "/tmp/packfile",
    # Not COATHANGER specific, but suspicious nonetheless:
    "/bin/busybox",
]

# Search all items in the following directories for recently modified binaries.
# If one has been changed while most of the others have not been, this could
# be an indicator of malicious activity.
MTIME_THRESHOLD = 60 * 60 * 24 * 7 * 4
MTIME_ITEMS = [
    # files
    "/bin/smartctl",
    "/data/bin/smartctl",
    "/bin/newcli",
    "/bin/sh",
    # folders
    "/bin",
    "/lib",
    "/data/bin",
    "/data/lib",
]

# Hidden folders in the following locations could be an indicator of COATHANGER.
# Some folders are legitimate, such as `.db`.
DATA_DIRS = ["/data", "/data2"]
DATA_DIRS_FP = [".db.x", ".db", ".fgtsum"]

IOCRecord = RecordDescriptor(
    "ioc/hit",
    [
        ("string", "type"),
        ("string", "alert"),
        ("string", "confidence"),
        ("string", "path"),
    ],
)


def check_target(target: Target) -> Optional[Iterator[IOCRecord]]:
    # I. Search for known-bad files
    log.info("Searching for suspicious files")
    file_hits = set()
    for file in SUSPICIOUS_FILES:
        if "*" in file:
            for path in target.fs.path(file.split("*")[0]).glob("*" + file.split("*")[-1]):
                file_hits.add(path)

        elif (path := target.fs.path(file)).exists():
            file_hits.add(path)

    for path in file_hits:
        yield IOCRecord(
            type="file",
            alert="Likely malicious COATHANGER file found",
            confidence="high",
            path=path,
        )

    # II. Scan using YARA rules
    log.info("Scanning using YARA rules")
    try:
        yara_file = Path(__file__).parent / "iocs" / "coathanger.yar"
        if not yara_file.exists():
            raise ValueError(f"COATHANGER YARA file not found at {yara_file}, could not scan using YARA.")

        if not target.has_function("yara"):
            raise ValueError(f"Could not run YARA function on target, have you installed yara?")

        for yara_hit in target.yara([yara_file]):
            yield IOCRecord(
                type="file/yara",
                alert="Likely malicious COATHANGER file found",
                confidence="high",
                path=yara_hit.path,
            )
    except (ImportError, ValueError, UnsupportedPluginError) as e:
        log.warning(str(e))

    # III. Search for non-standard hidden dirs in data dirs.
    log.info("Searching for non-standard hidden directories")
    for dir in DATA_DIRS:
        if not target.fs.path(dir).exists():
            continue

        for child in target.fs.path(dir).iterdir():
            if child.name[0:1] == "." and child.name not in DATA_DIRS_FP:
                yield IOCRecord(
                    type="file/hidden",
                    alert="Unexpected hidden folder found",
                    confidence="medium",
                    path=child,
                )

    # IV. Search for files which should have the approx. same mtime as their peers but don't.
    log.info("Searching for deviating file modification times")
    mtime_hits = []
    for entry in MTIME_ITEMS:
        path = target.fs.path(entry)
        if not path.exists():
            continue

        parent = path if path.is_dir() else path.parent
        children = [child for child in parent.iterdir() if child.exists()]
        if not children:
            continue

        children_median = statistics.median_grouped([child.stat().st_mtime for child in children])

        if path.is_dir():
            for child in children:
                child_mtime = child.stat().st_mtime
                if (child_mtime - children_median) > MTIME_THRESHOLD:
                    mtime_hits.append((child, child_mtime, children_median, "low"))

        else:
            file_mtime = path.stat().st_mtime
            if (file_mtime - children_median) > MTIME_THRESHOLD:
                mtime_hits.append((path, file_mtime, children_median, "medium"))

    for path, mtime, median, confidence in mtime_hits:
        yield IOCRecord(
            type="file/mtime",
            alert=f"File modification timestamp {uft(mtime)} deviates from median {uft(median)}",
            confidence=confidence,
            path=path,
        )


def main(target_paths: list, show_info: bool) -> None:
    for target_path in target_paths:
        if not Path(target_path).exists():
            log.warning(f"File {target_path} does not exist!")
            continue

        log.info(f"Scanning target {target_path}")
        target = Target.open(target_path)

        if target.os != "fortios":
            log.warning(f"Target {target_path} not recognised as a FortiOS system ({target.os}).")
            continue

        if show_info:
            print("")
            print_target_info(target)
            print("")

        hits = list(check_target(target))
        rows = []

        if hits:
            for hit in hits:
                rows.append(
                    {
                        "Confidence": hit.confidence,
                        "Type": hit.type,
                        "Alert": hit.alert,
                        "Source": hit.path,
                    }
                )

            log.warning(f"Found {len(hits)} COATHANGER indicators of compromise on system {target_path}")

            print("\n" + tabulate(rows, headers="keys") + "\n")

            print("")
            print("**********************************************************************************************")
            print("*                                                                                            *")
            print("*            COATHANGER Indicators of compromise (IOCs) were found on the system!            *")
            print("* Consider performing further forensic investigation to determine if the system is infected. *")
            print("*                                                                                            *")
            print("**********************************************************************************************")
            print("")

        else:
            log.info(f"No COATHANGER IOCs found on target {target.hostname}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyse forensic images of FortiGate systems for COATHANGER IOCs")
    parser.add_argument("targets", nargs="+", help="path(s) of target(s) to check")
    parser.add_argument("--info", action="store_true", help="print basic FortiGate system information")
    args = parser.parse_args()

    print(textwrap.dedent('''
      ____ ___    _  _____ _   _    _    _   _  ____ _____ ____
     / ___/ _ \\  / \\|_   _| | | |  / \\  | \\ | |/ ___| ____|  _ \\
    | |  | | | |/ _ \\ | | | |_| | / _ \\ |  \\| | |  _|  _| | |_) |
    | |__| |_| / ___ \\| | |  _  |/ ___ \\| |\\  | |_| | |___|  _ <
     \\____\\___/_/   \\_\\_| |_| |_/_/   \\_\\_| \\_|\\____|_____|_| \\_\\


    COATHANGER FortiGate IOC Checker
    https://github.com/JSCU-NL/COATHANGER

    '''))

    try:
        main(args.targets, args.info)
    except Exception as e:
        log.error("The script has crashed!", exc_info=e)

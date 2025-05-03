#!/usr/bin/env python3

import sys
import json
import os
import datetime
import subprocess
from pathlib import PureWindowsPath, PurePosixPath

# Set log path based on OS
if os.name == "nt":
    LOG_FILE = (
        "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
    )
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

# Helper to log debug messages
def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        ar_name_posix = str(
            PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):]))
        )
        log_file.write(
            str(datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
            + " "
            + ar_name_posix
            + ": "
            + msg
            + "\n"
        )

# Log YARA detection results
def write_log_yara(msg):
    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(msg)

# Main execution
def main(argv):
    write_debug_file(argv[0], "Starting Yara Engine")

    input_str = ""
    for line in sys.stdin:
        input_str += line
        break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except json.JSONDecodeError as e:
        write_debug_file(argv[0], f"[ERROR] Failed to parse JSON: {e}")
        sys.exit(1)

    filename = data["parameters"]["alert"]["syscheck"]["path"]
    write_debug_file(argv[0], f"Target file: {filename}")

    try:
        command = f"yara -C -w -r -f -m /home/<USERNAME>/compiled-rules.yar '{filename}'"
        yara_output = subprocess.run(
            command, shell=True, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        write_debug_file(argv[0], f"YARA scan completed:\n{yara_output.stdout}")
    except subprocess.CalledProcessError as e:
        write_debug_file(argv[0], f"[YARA ERROR] {e}")
        return
    except Exception as e:
        write_debug_file(argv[0], f"[SCRIPT ERROR] {e}")
        return

    if yara_output.stdout.strip():
        for line in yara_output.stdout.splitlines():
            write_log_yara(f"wazuh-yara: INFO - Scan result: {line}\n")

        quarantine_path = "/tmp/quarantined"
        os.makedirs(quarantine_path, exist_ok=True)

        try:
            mv_command = f"mv '{filename}' '{quarantine_path}/'"
            subprocess.run(mv_command, shell=True, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            write_debug_file(argv[0], f"Moved {filename} to {quarantine_path}")
        except Exception as e:
            write_debug_file(argv[0], f"[MOVE ERROR] {e}")

    print("Execution Success\n")

if __name__ == "__main__":
    main(sys.argv)

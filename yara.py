 #!/usr/bin/python3
 import sys
 import json
 import os
 import datetime
 import subprocess
 from pathlib import PureWindowsPath, PurePosixPath


 if os.name == "nt":
     LOG_FILE = (
         "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
     )
 else:
     LOG_FILE = "/var/ossec/logs/active-responses.log"


 def write_debug_file(ar_name, msg):
     with open(LOG_FILE, mode="a") as log_file:
         ar_name_posix = str(
             PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response") :]))
         )
         log_file.write(
             str(datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
             + " "
             + ar_name_posix
             + ": "
             + msg
             + "\n"
         )

 def write_log_yara(msg):
     with open(LOG_FILE, mode="a") as log_file:
         log_file.write(msg)


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
         write_debug_file(argv[0], "disana")
         print(f"Error parsing JSON: {e}")
         sys.exit(1)
     filename = data["parameters"]["alert"]["syscheck"]["path"]
     write_debug_file(argv[0], filename)
     write_debug_file(argv[0], "sini gaaa")
     try:
         command = f"yara -C -w -r -f -m /home/<USERNAME>/compiled-rules.yar {filename}"
         yara_output = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
         write_debug_file(argv[0], f"YARA scan completed: {yara_output.stdout}")
     except subprocess.CalledProcessError as e:
         write_debug_file(argv[0], str(e))
     except Exception as e:
         write_debug_file(argv[0], str(e))

     if yara_output.stdout.strip():
         for line in yara_output.stdout.splitlines():
             write_log_yara(f"wazuh-yara: INFO - Scan result: {line}")
         quarantine_path = "/tmp/quarantined"
         os.makedirs(quarantine_path, exist_ok=True)
         command = f"mv {filename} {quarantine_path}"
         subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
         write_debug_file(argv[0], f"{filename} moved to {quarantine_path}")

     print("Execution Success\n")


 if __name__ == "__main__":
     main(sys.argv)


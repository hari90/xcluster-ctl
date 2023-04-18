import datetime
import os
from pathlib import Path
import shutil
import subprocess
import re
import urllib3
urllib3.disable_warnings()

import requests

class Color:
    RED = "\033[31m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    YELLOW = "\033[33m"
    RESET = '\033[0m'

# Define color escape codes
GREEN = '\033[92m'
ENDC = '\033[0m'


def log(*values: object):
    log_to_file(*values)
    print(*values,  Color.RESET)

def log_to_file(*values: object):
    message = ' '.join(map(str, values))
    color_pattern = r"\033\[\d+m"
    message = re.sub(color_pattern, "", message)

    current_time = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    # Open the file in append mode
    with open('xcluster_ctl_log.txt', 'a') as file:
        # Write timestamp and "hari" to file
        file.write(f"[{current_time}] {message}\n")

def raise_exception(message : str):
    log_to_file("Exception:", message)
    raise Exception(Color.RED+message+Color.RESET)

def http_get(url : str, ca_cert_path):
    log_to_file("Running http_get:", url)
    # print(url, ca_cert_path)
    response = requests.get(url, verify=ca_cert_path)
    if response.status_code == 200:
        log_to_file("Response:", response.text)
        return response.text
    else:
        raise_exception(f"Failed to fetch data from {url}. Status code:{response.status_code}")

def run_subprocess(*command:object):
    log_to_file("Running subprocess:", ' '.join(*command))
    sub_process = subprocess.Popen(*command,
                       shell=False,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)

    waited = False
    while True:
        try:
            returncode = sub_process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            returncode = None
        if returncode is not None:
            break
        waited = True
        print(".", end="", flush=True)
    if waited:
        print()

    if returncode != 0:
        error = sub_process.stderr.readlines()
        raise_exception(f"{error}. Return code: {returncode}")
    else:
        lines = []
        result = sub_process.stdout.readlines()
        for line in result:
            lines+=[str(line.decode("utf-8")).strip()]
        log_to_file("Result:", lines)
        return lines

def run_remotely(hostname : str, ssh_port: int, key_file : str, command : str):
    ssh_command_str = f"sudo ssh -i {key_file} -ostricthostkeychecking=no -p {ssh_port} yugabyte@{hostname}"
    ssh_command = ssh_command_str.split()
    ssh_command.append(f'{command}')
    return run_subprocess(ssh_command)

def grant_file_permissions(file_path : str):
    chmod_command_str = f"sudo chmod +rw {file_path}"
    return run_subprocess(chmod_command_str.split())

def copy_file_from_remote(hostname : str, ssh_port: int, key_file : str, from_path : str, to_path : str):
    scp_command_str = f"sudo scp -P {ssh_port} -i {key_file} yugabyte@{hostname}:{from_path} {to_path}"
    return run_subprocess(scp_command_str.split())

def copy_file_to_remote(hostname : str, ssh_port: int, key_file : str, from_path : str, to_path : str):
    mk_dir_str = f"mkdir -p {os.path.dirname(to_path)}"
    run_remotely(hostname, ssh_port, key_file, mk_dir_str)
    scp_command_str = f"sudo scp -P {ssh_port} -i {key_file} {from_path} yugabyte@{hostname}:{to_path}"
    return run_subprocess(scp_command_str.split())

def move_file(from_path : str, to_path : str):
    Path(os.path.dirname(to_path)).mkdir(parents=True, exist_ok=True)
    shutil.move(from_path, to_path)

def is_input_yes(question : str):
    answer = input(f"{question}? (yes/no): ")
    return answer.lower() in ["yes","y"]

def validate_guid(guid):
    # Regular expression pattern for GUID/UUID
    guid_pattern = re.compile(
        r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    )

    # Check if the input string matches the GUID pattern
    if not guid_pattern.match(guid):
        raise_exception(f"Invalid GUID: {guid}")

def wrap_color(color : str, text : str):
    return f"{color}{text}{Color.RESET}"
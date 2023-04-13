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

def http_get(url : str, ca_cert_path : str):
    # print(url, ca_cert_path)
    response = requests.get(url, verify=ca_cert_path)
    if response.status_code == 200:
        return response.text
    else:
        raise Exception("Failed to fetch data from {url}. Status code:", response.status_code)

def run_subprocess(*command:object):
    # print(*command)
    sub_process = subprocess.Popen(*command,
                       shell=False,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)

    # streamdata = sub_process.communicate()[0]
    result = sub_process.stdout.readlines()
    returncode = sub_process.poll()
    if returncode != 0:
        error = sub_process.stderr.readlines()
        raise_exception(f"{error}")
    else:
        lines = []
        for line in result:
            lines+=[str(line.decode("utf-8")).strip()]
        return lines

def run_remotely(hostname : str, key_file : str, command : str):
    ssh_command_str = f"sudo ssh -i {key_file} -ostricthostkeychecking=no -p 54422 yugabyte@{hostname}"
    ssh_command = ssh_command_str.split()
    ssh_command.append(f'{command}')
    return run_subprocess(ssh_command)

def grant_file_permissions(file_path : str):
    chmod_command_str = f"sudo chmod +rw {file_path}"
    return run_subprocess(chmod_command_str.split())

def copy_file_from_remote(hostname : str, key_file : str, from_path : str, to_path : str):
    scp_command_str = f"sudo scp -P 54422 -i {key_file} yugabyte@{hostname}:{from_path} {to_path}"
    return run_subprocess(scp_command_str.split())

def copy_file_to_remote(hostname : str, key_file : str, from_path : str, to_path : str):
    mk_dir_str = f"mkdir -p {os.path.dirname(to_path)}"
    run_remotely(hostname, key_file, mk_dir_str)
    scp_command_str = f"sudo scp -P 54422 -i {key_file} {from_path} yugabyte@{hostname}:{to_path}"
    return run_subprocess(scp_command_str.split())

def move_file(from_path : str, to_path : str):
    Path(os.path.dirname(to_path)).mkdir(parents=True, exist_ok=True)
    shutil.move(from_path, to_path)
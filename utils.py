import datetime
import subprocess
import sys
import warnings
# warnings.filterwarnings(action='ignore',message='Python 3.6 is no longer supported')
#import paramiko
from enum import Enum
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
    raise Exception(message+Color.RESET)

# def run_remotely_old(command : str, hostname : str, key_filename : str):
#     # Define the SSH connection parameters
#     username = 'yugabyte'

#     # Create an SSH client
#     client = paramiko.SSHClient()
#     client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

#     try:
#         print(hostname, username, key_filename)
#         # Connect to the remote host using the certificate file for authentication
#         client.connect(hostname, port=54422, username=username, key_filename=key_filename)

#         # Run the command to execute the hello.py script
#         stdin, stdout, stderr = client.exec_command(command)

#         # Print the output of the command
#         print(stdout.read().decode())

#     finally:
#         # Close the SSH connection
#         client.close()

def http_get(url : str, ca_cert_path : str):
    response = requests.get(url, verify=ca_cert_path)
    if response.status_code == 200:
        return response.text
    else:
        raise Exception("Failed to fetch data from {url}. Status code:", response.status_code)

def run_remotely(hostname : str, key_file : str, command : str):
    ssh_command_str = f"sudo ssh -i {key_file} -ostricthostkeychecking=no -p 54422 yugabyte@{hostname}"
    ssh_command = ssh_command_str.split()
    ssh_command.append(f'{command}')
    # print (ssh_command)
    ssh = subprocess.Popen(ssh_command,
                       shell=False,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    result = ssh.stdout.readlines()
    if result == []:
        error = ssh.stderr.readlines()
        log("ERROR: %s" % error)
    else:
        return result


def run_yb_admin(hostname : str, key_file : str, master_addresses: str, command : str):
    yb_admin_command = f"tserver/bin/yb-admin -master_addresses {master_addresses} --certs_dir_name yugabyte-tls-config/ {command}"
    return run_remotely(hostname, key_file, yb_admin_command)
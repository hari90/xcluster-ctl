import ipaddress
import json
import os
import sys
import time
from utils import *

config_file = "config.json"
ca_file = "ca.crt"

class UniverseConfig:
    initialized = False
    universe_uuid = ""
    universe_name = ""
    master_ips = ""
    tserver_ips = ""
    pem_file_path = ""
    ca_cert_path = ""
    master_addresses = ""
    master_ip_map = []
    master_web_server_map = []
    tserver_ip_map = []
    tserver_web_server_map = []

    def __str__(self):
        if not self.initialized:
            return "not initialized"

        return "{'universe_name': '" + self.universe_name + "', 'master_ips': '" + str(self.master_ip_map) + "', 'tserver_ips': '" + str(self.tserver_ip_map) + "'}"

    def InitMasterInfo(self):
        self.master_ip_map = [ip.strip() for ip in self.master_ips.split(",")]
        self.master_web_server_map=[]
        for ip in self.master_ip_map:
            self.master_web_server_map+= [f"https://{ip}:7000/"]

        self.master_addresses = ",".join(map('{0}:7100'.format, self.master_ip_map))


    def InitTserverInfo(self):
        self.tserver_ip_map = [ip.strip() for ip in self.tserver_ips.split(",")]
        self.tserver_web_server_map=[]
        for ip in self.tserver_ip_map:
            self.tserver_web_server_map+= [f"https://{ip}:7000/"]

        self.tserver_addresses = ",".join(map('{0}:7100'.format, self.tserver_ip_map))


primary_config = UniverseConfig()
standby_config = UniverseConfig()

def run_yb_admin(config: UniverseConfig, command : str):
    yb_admin_command = f"tserver/bin/yb-admin -master_addresses {config.master_addresses} --certs_dir_name yugabyte-tls-config/ {command}"
    return run_remotely(config.master_ip_map[0], config.pem_file_path, yb_admin_command)

def write_config_file():
    # Serialize objects to JSON
    config_dict = {
        "primary_config": primary_config.__dict__,
        "standby_config": standby_config.__dict__
    }

    # Serialize objects to JSON
    config_json = json.dumps(config_dict, indent=4)
    # Write JSON to file
    with open(config_file, "w") as f:
        f.write(config_json)


def read_config_file():
    # Load JSON data from file
    if not os.path.exists(config_file):
        return

    with open("config.json", "r") as f:
        config_json = f.read()

        try:
            # Deserialize JSON to dictionary
            config_dict = json.loads(config_json)
        except json.JSONDecodeError as e:
            return

        # Check if primary_config and standby_config are present in the dictionary
        if "primary_config" not in config_dict or "standby_config" not in config_dict:
            return

        primary_config.__dict__ = config_dict["primary_config"]
        standby_config.__dict__ = config_dict["standby_config"]

def is_configured():
    return primary_config.initialized and standby_config.initialized

def validate_ip_csv(ip_str : str):
    """
    Validate if a list is a CSV of IP addresses.

    Args:
        ip_str: List of strings to validate.

    Returns:
        void: Throws exception if validation failed.
    """
    # Split the string by commas and remove any leading/trailing whitespace
    ips = [ip.strip() for ip in ip_str.split(",")]

    if len(ips) == 0:
        raise_exception("Invalid list of ips")

    # Loop through the IPs and validate each one
    for ip in ips:
        # Use the ipaddress module to validate if the IP is valid
        ipaddress.ip_address(ip)

def get_universe_info(config : UniverseConfig):
    log("Getting universe info")
    flags = http_get(f"{config.master_web_server_map[0]}varz?raw", config.ca_cert_path)

    cluster_uuid_pattern = r"--cluster_uuid=(.+)"
    match = re.search(cluster_uuid_pattern, flags)
    if match:
        config.universe_uuid = match.group(1)
    else:
        raise_exception(f"Cannot find universe name for {config.master_addresses}")

    cluster_name_pattern = r"--metric_node_name=yb-\d+-(.+)-n.+"
    match = re.search(cluster_name_pattern, flags)
    if match:
        config.universe_name = match.group(1)
    else:
        raise_exception(f"Cannot find universe name for {config.master_addresses}")

def get_master_ips(master_ip : str, key_file : str):
    log(f"Getting master list")
    result = run_remotely(master_ip, key_file, "cat master/conf/server.conf | grep master_addresses $master_server_conf | awk -F '=' '{print $2}'")
    if len(result) != 1:
        raise_exception(f"Cannot find masters list")
    return ','.join([ip.strip().split(":")[0] for ip in result[0].split(",")])

def get_tserver_ips(config : UniverseConfig):
    log(f"Getting tserver list")
    ips = []
    result = run_yb_admin(config, f"list_all_tablet_servers")

    if len(result) <= 0:
        raise_exception(f"Cannot find tserver list")

    for lines in result[1:]:
        match = re.findall("\d+.\d+.\d+.\d+", str(lines.split()[1]))
        if len(match) != 1:
            raise_exception(f"Cannot find tserver list, {lines}")
        ips.append(match[0])

    if len(ips) == 0:
        raise_exception(f"Cannot find tserver list")

    return ','.join(ips)

def get_ca_cert(config: UniverseConfig):
    log(f"Getting {ca_file}")
    copy_file_from_remote(config.master_ip_map[0], config.pem_file_path, f"yugabyte-tls-config/{ca_file}" , ca_file)
    grant_file_permissions(ca_file)

def init_universe(config: UniverseConfig, master_ip : str, key_file : str):
    config.master_ips = get_master_ips(master_ip, key_file)
    config.pem_file_path = key_file
    config.InitMasterInfo()
    get_ca_cert(config)
    config.ca_cert_path = ca_file
    get_universe_info(config)
    config.ca_cert_path = f"universes/{config.universe_name}/{ca_file}"
    move_file(ca_file, config.ca_cert_path)
    config.tserver_ips = get_tserver_ips(config)
    config.InitTserverInfo()
    config.initialized=True

def copy_certs(from_config : UniverseConfig, to_config : UniverseConfig):
    log(f"Copying cert files to {to_config.universe_name}")
    nodes = set(to_config.master_ip_map).union(set(to_config.tserver_ip_map))
    for node in nodes:
        copy_file_to_remote(node, to_config.pem_file_path, from_config.ca_cert_path, f"yugabyte-tls-producer/{from_config.universe_uuid}_repl/{ca_file}")

def configure():
    # temp code
    read_config_file()

    # master_ips = input("Enter one Primary universe master IP: ")
    # ipaddress.ip_address(master_ips)

    # pem_file = input("Enter Primary universe ssh cert file path: ")
    # if not os.path.exists(pem_file):
    #     raise_exception("File", pem_file, "not found")
    # primary_config.pem_file_path = pem_file
    # init_universe(primary_config, primary_config.master_ip_map[0], primary_config.pem_file_path)

    # master_ips = input("Enter one Secondary universe master IP: ")
    # ipaddress.ip_address(master_ips)
    # standby_config.master_ips = master_ips

    # pem_file = input("Enter Standby universe ssh cert file path: ")
    # if not os.path.exists(pem_file):
    #     raise_exception("File", pem_file, "not found")
    # standby_config.pem_file_path = pem_file
    # init_universe(standby_config, standby_config.master_ip_map[0], standby_config.pem_file_path)

    copy_certs(primary_config, standby_config)
    copy_certs(standby_config, primary_config)

    write_config_file()
    show_config()

    log(Color.GREEN+"Successfully configured\n")
    validate_universes()

def show_config():
    log("Primary Universe:")
    log(Color.YELLOW+str(primary_config))
    log("Standby Universe:")
    log(Color.YELLOW+str(standby_config))


required_common_flags = {
    "xcluster_consistent_wal=true",
    "enable_pg_savepoints=false",
    "consensus_max_batch_size_bytes=1048576",
    "rpc_throttle_threshold_bytes=524288",
    "ysql_num_shards_per_tserver=3",
    # "yb_client_admin_operation_timeout_sec=600",
    "cdc_consumer_handler_thread_pool_size=200"
}

required_master_flags = required_common_flags.union({
    "enable_automatic_tablet_splitting=false",
    "enable_tablet_split_of_xcluster_replicated_tables=false"
})

required_tserver_flags = required_common_flags

def validate_flags(url : str, ca_cert_path : str, required_flags):
    set_flags = http_get(f"{url}varz?raw", ca_cert_path)

    for flag in required_flags:
        if flag not in set_flags:
            raise_exception(f"Required flag {Color.YELLOW}{flag}{Color.RESET} is not set on "+Color.YELLOW+url)

def validate_flags_on_universe(config: UniverseConfig):
    log(f"Validating flags on {config.universe_name}")
    for url in config.master_web_server_map:
        validate_flags(url, config.ca_cert_path, required_master_flags)
    for url in config.tserver_web_server_map:
        validate_flags(url, config.ca_cert_path, required_tserver_flags)

def validate_universes():
    validate_flags_on_universe(primary_config)
    validate_flags_on_universe(standby_config)
    log(Color.GREEN + "Universe validation successful")

def get_xcluster_safe_time_int():
    log(f"Getting xcluster_safe_time from {standby_config.universe_name}\n")
    xcluster_safe_time = run_yb_admin(standby_config, "get_xcluster_safe_time")
    namespace_id = ""
    uninitialized_safe_time : bool = len(xcluster_safe_time) == 0
    for line in xcluster_safe_time:
        value = line.split('":')
        if len(value) > 1:
            value = value[1].strip().replace('"','').replace(',','')
        if 'namespace_id"' in line:
            namespace_id=value
        if 'safe_time"' in line:
            log(f"namespace_id= {namespace_id}\nsafe_time= {value}")
            if "2023-" not in value:
                uninitialized_safe_time=True
    return uninitialized_safe_time


def get_xcluster_safe_time():
    while get_xcluster_safe_time_int():
        log(Color.YELLOW+"Some xcluster_safe_time are not initialized. Waiting...\n")
        time.sleep(2)
    log("\n"+Color.GREEN+"Successfully got xcluster_safe_time")

def set_standby_role():
    log(f"Setting {standby_config.universe_name} to STANDBY")
    run_yb_admin(standby_config, "change_xcluster_role STANDBY")
    # Wait for async processing
    time.sleep(2)
    log(Color.GREEN+"Successfully set role to STANDBY")

    get_xcluster_safe_time()

def set_active_role():
    log(f"Setting {standby_config.universe_name} to ACTIVE")
    run_yb_admin(standby_config, "change_xcluster_role ACTIVE")
    # Wait for async processing
    time.sleep(2)
    log(Color.GREEN+"Successfully set role to ACTIVE")

def main():
    # Define a dictionary to map user input to functions
    function_map = {
        "configure": configure,
        "show_config":show_config,
        "validate_universes": validate_universes,
        "set_standby_role" : set_standby_role,
        "set_active_role" : set_active_role,
        "get_xcluster_safe_time" : get_xcluster_safe_time,
    }

    usage_str=f"Usage: python3 {sys.argv[0]} <command> [args]\n"\
                "commands: \n\t"+'\n\t'.join(function_map)+"\n\n" \
                "'configure' must be run at least once\n"

    if len(sys.argv) != 2:
        print(usage_str)
        return

    user_input = sys.argv[1]

    log_to_file(' '.join(sys.argv))

    if user_input == "configure":
        configure()
        return

    read_config_file()

    if not is_configured():
        configure()

    if user_input in function_map:
        function_map[user_input]()
    else:
        print("Invalid input")
        print(usage_str)

if __name__ == "__main__":
    # Call the main function if the script is run directly
    main()
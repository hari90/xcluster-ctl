import ipaddress
import json
import os
import sys
from utils import *

config_file = "config.json"

class UniverseConfig:
    initialized = False
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

        return "{'universe_name': '" + self.universe_name + "', 'master_ips': '" + self.master_ips + "', 'tserver_ips': '" + self.tserver_ips + "', 'pem_file_path': '" + self.pem_file_path + "'}"

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

def get_universe_name(config : UniverseConfig):
    log("Getting universe name")
    flags = http_get(f"{config.master_web_server_map[0]}varz?raw", config.ca_cert_path)
    pattern = r"(?<=--metric_node_name=)(.+)-n.+"
    match = re.search(pattern, flags)
    if match:
        config.universe_name = match.group(1)
    else:
        raise_exception(f"Cannot find universe name for {config.master_addresses}")

def get_tserver_ips(config : UniverseConfig):
    log(f"Getting tserver list for {config.universe_name}")
    ips = []
    result = run_yb_admin(primary_config.master_ip_map[0],
        primary_config.pem_file_path, primary_config.master_addresses,  command="list_all_tablet_servers")

    if len(result) <= 0:
        raise_exception(f"Cannot find tserver list for {primary_config.universe_name}")

    for lines in result[1:]:
        match = re.findall("\d+.\d+.\d+.\d+", str(lines.split()[1]))
        if len(match) != 1:
            raise_exception(f"Cannot find tserver list for {primary_config.universe_name}, {lines}")
        ips.append(match[0])

    if len(ips) == 0:
        raise_exception(f"Cannot find tserver list for {primary_config.universe_name}")

    config.tserver_ips = ','.join(ips)

def configure():
    # master_ips = input("Enter Primary universe master IP csv list: ")
    # validate_ip_csv(master_ips)
    # primary_config.master_ips = master_ips

    # pem_file = input("Enter Primary universe ssh cert file path: ")
    # if not os.path.exists(pem_file):
    #     raise_exception("File", pem_file, "not found")
    # primary_config.pem_file_path = pem_file
    # primary_config.ca_cert_path = "primary_cert/ca.crt"
    primary_config.InitMasterInfo()
    get_universe_name(primary_config)
    get_tserver_ips(primary_config)
    primary_config.InitTserverInfo()

    # master_ips = input("Enter Standby universe master IP csv list: ")
    # validate_ip_csv(master_ips)
    # standby_config.master_ips = master_ips

    # pem_file = input("Enter Standby universe ssh cert file path: ")
    # if not os.path.exists(pem_file):
    #     raise_exception("File", pem_file, "not found")
    # standby_config.pem_file_path = pem_file
    # standby_config.ca_cert_path = "standby_cert/ca.crt"
    standby_config.InitMasterInfo()
    get_universe_name(standby_config)
    get_tserver_ips(standby_config)
    standby_config.InitTserverInfo()

    write_config_file()
    show_config()

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
            raise_exception(f"Required flag {Color.RED}{flag}{Color.RESET} is not set on "+Color.RED+url)

def validate_universes():
    log(f"Validating flags on {primary_config.universe_name}")
    for url in primary_config.master_web_server_map:
        validate_flags(url, primary_config.ca_cert_path, required_master_flags)
    for url in primary_config.tserver_web_server_map:
        validate_flags(url, primary_config.ca_cert_path, required_tserver_flags)


    log(f"Validating flags on {standby_config.universe_name}")
    for url in standby_config.master_web_server_map:
        validate_flags(url, standby_config.ca_cert_path, required_master_flags)
    for url in standby_config.tserver_web_server_map:
        validate_flags(url, standby_config.ca_cert_path, required_tserver_flags)

    log(Color.GREEN + "Universe validation Successful")

def main():
    # Define a dictionary to map user input to functions
    function_map = {
        "configure": configure,
        "show_config":show_config,
        "validate_universes": validate_universes
    }

    usage_str=f"Usage: python3 {sys.argv[0]} [{' '.join(function_map)}]"

    if len(sys.argv) != 2:
        print(usage_str)
        return

    read_config_file()

    user_input = sys.argv[1]

    log_to_file(' '.join(sys.argv))

    if not is_configured():
        configure()
        if user_input == "configure":
            return

    if user_input in function_map:
        function_map[user_input]()
    else:
        print("Invalid input")
        print(usage_str)

if __name__ == "__main__":
    # Call the main function if the script is run directly
    main()
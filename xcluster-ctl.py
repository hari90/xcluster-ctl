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
    ssh_port = 0
    master_addresses = ""
    master_ip_map = []
    master_web_server_map = []
    tserver_ip_map = []
    tserver_web_server_map = []
    bootstrap_table_ids = []
    bootstrap_ids = []
    role = ""

    def __str__(self):
        if not self.initialized:
            return "not initialized"

        return "{'universe_name': '" + self.universe_name + "', 'master_ips': '" + str(self.master_ip_map) + "', 'tserver_ips': '" + str(self.tserver_ip_map) + \
                "', 'role': '" + self.role + "'}"

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
    return run_remotely(config.master_ip_map[0], config.ssh_port, config.pem_file_path, yb_admin_command)

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

def print_header():
    log(f"[ {Color.BLUE}{primary_config.universe_name}{Color.RESET} -> {Color.BLUE}{standby_config.universe_name}{Color.RESET} ]")

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

def get_flags(url : str, ca_cert_path: str):
    return http_get(f"{url}varz?raw", ca_cert_path)

def get_universe_info(config : UniverseConfig):
    log("Getting universe info")
    flags = get_flags(config.master_web_server_map[0], config.ca_cert_path)

    cluster_uuid_pattern = r"--cluster_uuid=(.+)"
    match = re.search(cluster_uuid_pattern, flags)
    if match:
        config.universe_uuid = match.group(1)
    else:
        raise_exception(f"Cannot find universe uuid for {config.master_addresses}")

    cluster_name_pattern = r"--metric_node_name=(.+)-n.+"
    match = re.search(cluster_name_pattern, flags)
    if match:
        config.universe_name = match.group(1)
    else:
        raise_exception(f"Cannot find universe name for {config.master_addresses}")

def get_master_ips(master_ip : str, ssh_port: int, key_file : str):
    log(f"Getting master list")
    result = run_remotely(master_ip, ssh_port, key_file, "cat master/conf/server.conf | grep master_addresses $master_server_conf | awk -F '=' '{print $2}'")
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
    copy_file_from_remote(config.master_ip_map[0], config.ssh_port, config.pem_file_path, f"yugabyte-tls-config/{ca_file}" , ca_file)
    grant_file_permissions(ca_file)

def init_universe(config: UniverseConfig, master_ip : str, ssh_port : int, key_file : str):
    config.master_ips = get_master_ips(master_ip, ssh_port, key_file)
    config.ssh_port = ssh_port
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
        copy_file_to_remote(node, to_config.ssh_port, to_config.pem_file_path, from_config.ca_cert_path, f"yugabyte-tls-producer/{from_config.universe_uuid}_repl/{ca_file}")

def get_cluster_config_from_user(cluster_type : str):
    ssh_port_str = input(f"Enter {cluster_type} universe ssh port (default is 54422): ")
    if ssh_port_str.strip() == "":
        ssh_port = 54422
    else:
        ssh_port = int(ssh_port_str)
        if ssh_port <= 0:
            raise_exception("Invalid port number")

    pem_file = input(f"Enter {cluster_type} universe ssh cert file path: ")
    if not os.path.exists(pem_file):
        raise_exception(f"File {pem_file} not found")

    return ssh_port, pem_file

def configure(args):
    master_ips = input(f"Enter one Primary universe master IP: ")
    ipaddress.ip_address(master_ips)

    ssh_port, pem_file = get_cluster_config_from_user("Primary")
    init_universe(primary_config, master_ips, ssh_port, pem_file)

    master_ips = input("Enter one Secondary universe master IP: ")
    ipaddress.ip_address(master_ips)

    log(f"\nssh port:\t\t{ssh_port}\nssh cert file path:\t{pem_file}")
    if not is_input_yes("Do you want to use these settings for the Seconday universe as well"):
        ssh_port, pem_file = get_cluster_config_from_user("Seconday")
    init_universe(standby_config, master_ips, ssh_port, pem_file)

    if primary_config.universe_uuid == standby_config.universe_uuid:
        raise_exception("Both universes are the same")

    copy_certs(primary_config, standby_config)
    copy_certs(standby_config, primary_config)

    reload_roles(args)

    log(Color.GREEN+"Successfully configured\n")
    validate_universes([])

def show_config(args):
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
    "cdc_consumer_handler_thread_pool_size=200",
    # Optional flags
    # db_block_cache_size_percentage=20,
    # yb_client_admin_operation_timeout_sec=600,
}

required_master_flags = required_common_flags.union({
    "enable_automatic_tablet_splitting=false",
    "enable_tablet_split_of_xcluster_replicated_tables=false",
    "cdc_wal_retention_time_secs=900"
})

required_tserver_flags = required_common_flags

def validate_flags(url : str, ca_cert_path : str, required_flags, universe_name : str):
    set_flags = get_flags(url, ca_cert_path)

    for flag in required_flags:
        if flag not in set_flags:
            raise_exception(f"Required flag {Color.YELLOW}{flag}{Color.RESET} is not set on {Color.YELLOW}{universe_name} {url}")

def validate_flags_on_universe(config: UniverseConfig):
    log(f"Validating flags on {config.universe_name}")
    for url in config.master_web_server_map:
        validate_flags(url, config.ca_cert_path, required_master_flags, config.universe_name)
    for url in config.tserver_web_server_map:
        validate_flags(url, config.ca_cert_path, required_tserver_flags, config.universe_name)

def validate_universes(args):
    validate_flags_on_universe(primary_config)
    validate_flags_on_universe(standby_config)
    log(Color.GREEN + "Universe validation successful")

def get_xcluster_safe_time_int():
    log(f"Getting xcluster_safe_time from {standby_config.universe_name}\n")
    log(f"Current_time:\t\t{datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%s')}")
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
            log(f"\nnamespace_id:\t\t{namespace_id}\nxcluster_safe_time:\t{value}")
            if "2023-" not in value:
                uninitialized_safe_time=True
    return uninitialized_safe_time

def get_xcluster_estimated_data_loss(args):
    log(f"Getting estimated data loss from {standby_config.universe_name}")
    xcluster_safe_time = run_yb_admin(standby_config, "get_xcluster_estimated_data_loss")
    namespace_id = ""
    for line in xcluster_safe_time:
        value = line.split('":')
        if len(value) > 1:
            value = value[1].strip().replace('"','').replace(',','')
        if 'namespace_id"' in line:
            log(f"\nnamespace_id:\t\t{value}")
        if 'data_loss_sec"' in line:
            log(f"data_loss_sec:\t\t{value}")

    log("\n"+Color.GREEN+"Successfully got estimated data loss")

def get_xcluster_safe_time(args):
    while get_xcluster_safe_time_int():
        log(Color.YELLOW+"Some xcluster_safe_time are not initialized. Waiting...\n")
        time.sleep(2)
    log("\n"+Color.GREEN+"Successfully got xcluster_safe_time")

def is_standy_role(config: UniverseConfig):
    result = http_get(f"{config.master_web_server_map[0]}xcluster-config", config.ca_cert_path)
    return "role: STANDBY" in result

def set_standby_role(args):
    log(f"Setting {standby_config.universe_name} to STANDBY")
    if standby_config.role != "STANDBY":
        run_yb_admin(standby_config, "change_xcluster_role STANDBY")
        standby_config.role = "STANDBY"
        write_config_file()
        # Wait for async processing
        time.sleep(2)
    log(Color.GREEN+"Successfully set role to STANDBY")

    get_xcluster_safe_time([])

def set_active_role(args):
    log(f"Setting {standby_config.universe_name} to ACTIVE")

    if standby_config.role != "ACTIVE":
        run_yb_admin(standby_config, "change_xcluster_role ACTIVE")
        standby_config.role = "ACTIVE"
        write_config_file()
    # Wait for async processing
    time.sleep(2)
    log(Color.GREEN+"Successfully set role to ACTIVE")

def get_cdc_streams():
    log("Getting replication streams")
    data = run_yb_admin(primary_config, "list_cdc_streams")
    stream_ids = []
    for line in data:
        if 'stream_id:' in line:
            stream_id = line.split(':')[-1].strip().strip('"')
            stream_ids.append(stream_id)
    log(f"Found {len(stream_ids)} replication streams")
    log_to_file(stream_ids)
    return stream_ids

def is_replication_drain_done(stream_ids):
    result = ''.join(run_yb_admin(primary_config, "wait_for_replication_drain "+','.join(stream_ids)))
    done = "undrained" not in result
    if not done:
        log(Color.YELLOW+result)
    else:
        log(result)
    return done

def wait_for_replication_drain(args):
    stream_ids = get_cdc_streams()
    if len(stream_ids) == 0:
        raise_exception("No replication in progress")

    log("Waiting for replication drain...")
    while not is_replication_drain_done(stream_ids):
        time.sleep(1)
    log(Color.GREEN+"Successfully completed wait for replication drain")

def get_table_ids(databases):
    log(f"Getting tables for database(s) {','.join(databases)} from {primary_config.universe_name}")
    table_ids = []
    result = run_yb_admin(primary_config, f"list_tables include_table_id include_table_type")
    for table_and_db in result:
        match = False
        for database in databases:
            pattern = f"^{database}.*(?<!catalog)$"
            re_match = re.match(pattern, table_and_db)
            if re_match:
                match = True
                break
        if match:
            table_ids += [table_and_db.split(' ')[1]]

    log_to_file(table_ids)
    return table_ids

def delete_cdc_streams(stream_id):
    result = run_yb_admin(primary_config, f"delete_cdc_stream {stream_id} force_delete")
    log_to_file(result)

def bootstrap_tables(table_ids):
    log(f"Bootstrapping {len(table_ids)} tables")

    result = run_yb_admin(primary_config, "bootstrap_cdc_producer "+','.join(table_ids))
    bootstrap_ids = []
    for line in result:
        bootstrap_ids.append(line.split(':')[-1].strip())

    log_to_file(bootstrap_ids)
    return bootstrap_ids

def bootstrap_databases(args):
    if len(primary_config.bootstrap_table_ids) > 0:
        raise_exception("There is already an available bootstrap. Run setup_replication_with_bootstrap")

    if len(args) != 1:
        databases = input("Please provide a CSV list of database names to bootstrap: ")
    else:
        databases = args[0]
    table_ids = get_table_ids(databases.split(','))

    if len(table_ids) == 0:
        raise_exception("No tables found")

    bootstrap_ids = bootstrap_tables(table_ids)

    primary_config.bootstrap_table_ids = table_ids
    primary_config.bootstrap_ids = bootstrap_ids
    write_config_file()

    log(Color.GREEN+"Successfully bootstrapped databases. Run setup_replication_with_bootstrap to complete setup")

def clear_bootstrap_from_config():
    primary_config.bootstrap_table_ids = []
    primary_config.bootstrap_ids = []
    write_config_file()

def clear_bootstrap(args):
    if len(primary_config.bootstrap_ids) == 0:
        log(Color.GREEN+"No pending bootstraps to clear")
        return

    log(f"Deleting {len(primary_config.bootstrap_ids)} streams")
    for bootstrap in primary_config.bootstrap_ids:
        delete_cdc_streams(bootstrap)

    clear_bootstrap_from_config()

    log(Color.GREEN+"Successfully cleared bootstrap")

def setup_replication_with_bootstrap(args):
    if len(primary_config.bootstrap_ids) == 0:
        bootstrap_databases(args)

    log(f"Setting up replication from {primary_config.universe_name} to {standby_config.universe_name} with bootstrap")

    result = run_yb_admin(standby_config, f"setup_universe_replication {primary_config.universe_uuid}_repl {primary_config.master_addresses} {','.join(primary_config.bootstrap_table_ids)} {','.join(primary_config.bootstrap_ids)}")
    log('\n'.join(result))

    clear_bootstrap_from_config()

    log(Color.GREEN+"Successfully setup replication")
    set_standby_role(args)

def setup_replication(args):
    if len(primary_config.bootstrap_ids) > 0:
        raise_exception("There is already an available bootstrap. Run setup_replication_with_bootstrap")

    log(f"Setting up replication from {primary_config.universe_name} to {standby_config.universe_name} without bootstrap")

    if len(args) != 1:
        databases = input("Please provide a CSV list of database names to bootstrap: ")
    else:
        databases = args[0]
    table_ids = get_table_ids(databases.split(','))

    if len(table_ids) == 0:
        raise_exception("No tables found")

    result = run_yb_admin(standby_config, f"setup_universe_replication {primary_config.universe_uuid}_repl {primary_config.master_addresses} {','.join(table_ids)}")
    log('\n'.join(result))

    log(Color.GREEN+"Successfully setup replication")
    set_standby_role(args)

def delete_replication(args):
    replication_name, stream_count, role = get_replication_info_int()
    log(f"Deleting replication {replication_name} from {primary_config.universe_name} to {standby_config.universe_name}")
    result = run_yb_admin(standby_config, f"delete_universe_replication {primary_config.universe_uuid}_{replication_name}")
    log('\n'.join(result))
    log(Color.GREEN+"Successfully deleted replication")

def pause_replication(args):
    log(f"Pausing replication from {primary_config.universe_name} to {standby_config.universe_name}")
    result = run_yb_admin(standby_config, f"set_universe_replication_enabled {primary_config.universe_uuid}_repl 0")
    log('\n'.join(result))
    log(Color.GREEN+"Successfully paused replication")

def resume_replication(args):
    log(f"Resuming replication from {primary_config.universe_name} to {standby_config.universe_name}")
    result = run_yb_admin(standby_config, f"set_universe_replication_enabled {primary_config.universe_uuid}_repl 1")
    log('\n'.join(result))
    log(Color.GREEN+"Successfully resumed replication")

def swap_universe_configs(args):
    log(f"Swapping Primay and Standby universes")
    global standby_config, primary_config
    temp = standby_config
    standby_config = primary_config
    primary_config = temp

    write_config_file()
    print_header()

def planned_failover(args):
    log(f"Performing a planned failover from {primary_config.universe_name} to {standby_config.universe_name}")
    wait_for_replication_drain(args)
    get_xcluster_safe_time(args)
    if not is_input_yes("Are you sure you want to proceed"):
        log(Color.YELLOW+"Planned failover abandoned")
        return
    set_active_role(args)
    delete_replication(args)
    swap_universe_configs(args)
    setup_replication_with_bootstrap(args)

    log(Color.GREEN+f"Successfully failed over from {standby_config.universe_name} to {primary_config.universe_name}")

def unplanned_failover(args):
    log(f"Performing a unplanned failover from {primary_config.universe_name} to {standby_config.universe_name}")
    pause_replication(args)
    get_xcluster_estimated_data_loss(args)
    get_xcluster_safe_time(args)
    if not is_input_yes("Are you sure you want to proceed"):
        log(Color.YELLOW+"Planned failover abandoned")
        return

    log(Color.YELLOW+"\nUse YBA to restore the databases to the xcluster safe time\n")
    if not is_input_yes("Did the point in time restore complete"):
        log(Color.YELLOW+"Planned failover abandoned")
        return

    set_active_role(args)
    delete_replication(args)
    swap_universe_configs(args)

    log(Color.YELLOW+f"\nOnce {standby_config.universe_name} comes back online drop its database and recreate the database schema. Then use YBA to setup replication with backup and restore. After it completes run set_standby_role\n")

    log(Color.GREEN+f"Successfully failed over from {standby_config.universe_name} to {primary_config.universe_name}")

def reload_roles(args):
    if is_standy_role(primary_config):
        primary_config.role = "STANDBY"
    else:
        primary_config.role = "ACTIVE"

    if is_standy_role(standby_config):
        standby_config.role = "STANDBY"
    else:
        standby_config.role = "ACTIVE"

    write_config_file()
    show_config(args)

def add_table(args):
    log("Coming soon")

def remove_table(args):
    log("Coming soon")

def extract_consumer_registry(data: str):
    lines = data.splitlines()
    role = "ACTIVE"
    universe_uuid = ""
    replication_name = ""
    in_consumer_registry = False
    stream_count = 0
    i = 0
    while i < len(lines):
        line = lines[i]
        i = i + 1
        if "consumer_registry" in line:
            in_consumer_registry = True
        if not in_consumer_registry:
            continue

        if "role: STANDBY" in line:
            role="STANDBY"

        if "producer_map" in line:
            if universe_uuid != "":
                raise_exception("Multiple replication groups found. Only one replication group is supported")
            line = lines[i]
            i = i + 1
            replication_key_pattern = r'key: "(.*)_(.*)"'
            match = re.search(replication_key_pattern, line)
            if match:
                universe_uuid = match.group(1)
                replication_name = match.group(2)
            else:
                raise_exception(f"Cannot parse replication key {line}")
            if universe_uuid != primary_config.universe_uuid:
                raise_exception(f"Expected replication from {primary_config.universe_name} {primary_config.universe_uuid}, but found {universe_uuid}. Rerun 'configure' with the correct Primary and Standby universes")

        if "stream_map" in line:
            stream_count+=1

    if replication_name == "" or stream_count == 0:
        raise_exception("No replication in progress")

    return replication_name, stream_count, role


def get_replication_info_int():
    log("Getting current replication info")
    result = http_get(f"{standby_config.master_web_server_map[0]}xcluster-config", standby_config.ca_cert_path)
    return extract_consumer_registry(result)

def get_replication_info(args):
    replication_name, stream_count, role = get_replication_info_int()
    log(f"{Color.GREEN}Found replication group {Color.YELLOW}{replication_name}{Color.GREEN} with {Color.YELLOW}{stream_count}{Color.GREEN} tables")
    if role != "STANDBY":
        log(f"{Color.RED}STANDBY role has not been set on {Color.RESET}{standby_config.universe_name}{Color.RED}. Please run 'set_standby_role'")

def main():
    # Define a dictionary to map user input to functions
    function_map = {
        "configure": configure,
        "show_config":show_config,
        "validate_universes": validate_universes,
        "setup_replication" : setup_replication,
        "setup_replication_with_bootstrap" : setup_replication_with_bootstrap,
        "get_replication_info" : get_replication_info,
        "set_standby_role" : set_standby_role,
        "set_active_role" : set_active_role,
        "get_xcluster_safe_time" : get_xcluster_safe_time,
        "planned_failover" : planned_failover,
        "unplanned_failover" : unplanned_failover,
        "add_table" : add_table,
        "remove_table" : remove_table,
        "wait_for_replication_drain" : wait_for_replication_drain,
        "bootstrap_databases" : bootstrap_databases,
        "clear_bootstrap" : clear_bootstrap,
        "delete_replication" : delete_replication,
        "reload_roles" : reload_roles,
        "switch_universe_configs" : swap_universe_configs,
        "get_xcluster_estimated_data_loss" : get_xcluster_estimated_data_loss,
        "pause_replication" : pause_replication,
        "resume_replication" : resume_replication,
    }

    usage_str=f"Usage: python3 {sys.argv[0]} <command> [args]\n"\
                "commands: \n\t"+'\n\t'.join(function_map)+"\n\n" \
                "'configure' must be run at least once\n"

    if len(sys.argv) < 2:
        print(usage_str)
        return

    user_input = sys.argv[1]

    log_to_file(' '.join(sys.argv))

    if user_input == "configure":
        configure([])
        return

    read_config_file()

    if not is_configured():
        configure([])

    print_header()
    if user_input in function_map:
        function_map[user_input](sys.argv[2:])
    else:
        print("Invalid input")
        print(usage_str)

if __name__ == "__main__":
    # Call the main function if the script is run directly
    main()
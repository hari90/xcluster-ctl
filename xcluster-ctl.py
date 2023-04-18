import datetime
import ipaddress
import json
import os
import sys
import time
from urllib.parse import urlsplit, urlunsplit
from utils import *

config_file = "config.json"
ca_file = "ca.crt"

class PortalConfig:
    url = ""
    customer_id = ""
    token = ""

    def __str__(self):
        return "{'url': '" + self.url + "', 'customer_id': '" + self.customer_id + "', 'token': '" + self.token + "'}"

portal_config = PortalConfig()

class BootstrapInfo:
    initialized = False
    databses = []
    table_ids = []
    bootstrap_ids = []
    def __str__(self):
        if not self.initialized:
            return "Not initialized"

        return "{'databses': '" + str(self.databses) + "', 'table_ids': '" + str(self.table_ids) + "', 'bootstrap_ids': '" + str(self.bootstrap_ids) + "'}"

bootstrap_info = BootstrapInfo()

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
    role = ""

    def __str__(self):
        if not self.initialized:
            return "Not initialized"

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
        "portal_config": portal_config.__dict__,
        "primary_config": primary_config.__dict__,
        "standby_config": standby_config.__dict__,
        "bootstrap_info": bootstrap_info.__dict__
    }

    # Serialize objects to JSON
    config_json = json.dumps(config_dict, indent=4)
    log_to_file("New Config",config_json)

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

        portal_config.__dict__ = config_dict["portal_config"]
        primary_config.__dict__ = config_dict["primary_config"]
        standby_config.__dict__ = config_dict["standby_config"]
        bootstrap_info.__dict__ = config_dict["bootstrap_info"]

def is_configured():
    return primary_config.initialized and standby_config.initialized

def print_header():
    log(f"[ {wrap_color(Color.BLUE, primary_config.universe_name)} -> {wrap_color(Color.BLUE, standby_config.universe_name)} ]")

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
    full_url = input("Enter the portal url: ")
    url_parts = urlsplit(full_url)
    portal_config.url = urlunsplit((url_parts.scheme, url_parts.netloc, '', '', ''))
    if len(portal_config.url) == 0:
        raise_exception("Portal url cannot be empty")

    # log(http_get(f"{portal_config.url}/profile", False))
    log(f"Get the Customer ID and API Token from {Color.YELLOW}{portal_config.url}/profile")
    portal_config.customer_id = input("Enter the customer id: ")
    if portal_config.customer_id.strip() == "":
        raise_exception("Customer id cannot be empty")
    validate_guid(portal_config.customer_id)

    portal_config.token = input("Enter the auth token: ")
    if portal_config.token.strip() == "":
        raise_exception("Auth token cannot be empty")
    validate_guid(portal_config.token)

    master_ips = input(f"\nEnter one Primary universe master IP: ")
    ipaddress.ip_address(master_ips)

    ssh_port, pem_file = get_cluster_config_from_user("Primary")
    init_universe(primary_config, master_ips, ssh_port, pem_file)

    master_ips = input("\nEnter one Secondary universe master IP: ")
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
    log("Portal Config:")
    log(Color.YELLOW+str(portal_config))
    log("Primary Universe:")
    log(Color.YELLOW+str(primary_config))
    log("Standby Universe:")
    log(Color.YELLOW+str(standby_config))
    if bootstrap_info.initialized:
        log("Bootstrap Info:")
        log(Color.YELLOW+str(bootstrap_info))


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
            raise_exception(f"Required flag {wrap_color(Color.YELLOW, flag)} is not set on {wrap_color(Color.YELLOW, universe_name)} {wrap_color(Color.YELLOW, url)}")

def validate_flags_on_universe(config: UniverseConfig):
    log(f"Validating flags on {Color.YELLOW}{config.universe_name}")
    for url in config.master_web_server_map:
        validate_flags(url, config.ca_cert_path, required_master_flags, config.universe_name)
    for url in config.tserver_web_server_map:
        validate_flags(url, config.ca_cert_path, required_tserver_flags, config.universe_name)

def validate_universes(args):
    validate_flags_on_universe(primary_config)
    validate_flags_on_universe(standby_config)
    log(Color.GREEN + "Universe validation successful")

def sync_portal(args):
    log_to_file(f"Synching Poral @{portal_config.url}")
    # curl -k --location --request POST 'https://portal.dev.yugabyte.com/api/v1/customers/11d78d93-1381-4d1d-8393-ba76f47ba7a6/xcluster_configs/sync?targetUniverseUUID=76b9e2c2-8e29-45cf-a6fd-daa7dfe1b993' --header 'X-AUTH-YW-API-TOKEN: 244b3ac7-63bc-47c3-0' --data ''

    request_url = f"{portal_config.url}/api/v1/customers/{portal_config.customer_id}/xcluster_configs/sync?targetUniverseUUID={standby_config.universe_uuid}"
    headers = {
    "X-AUTH-YW-API-TOKEN": portal_config.token
    }
    payload = ""
    response = requests.request("POST", request_url, headers=headers, data=payload, verify=False)

    if response.status_code == 200:
        log_to_file(response.text)
    else:
        log_to_file(response.status_code, request_url, headers)
        raise_exception(f"Failed to sync Portal. Status code:{response.status_code}")

    log(Color.GREEN + "Successfully synced Portal")

def get_xcluster_safe_time_int():
    log(f"Getting xcluster_safe_time from {standby_config.universe_name}")
    database_map = get_databases(standby_config)
    xcluster_safe_time = run_yb_admin(standby_config, "get_xcluster_safe_time")
    database_safe_time_map={}
    database_name = ""
    uninitialized_safe_time : bool = len(xcluster_safe_time) == 0
    for line in xcluster_safe_time:
        value = line.split('":')
        if len(value) > 1:
            value = value[1].strip().replace('"','').replace(',','')
        if 'namespace_id"' in line:
            if value not in database_map:
                raise_exception(f"Cannot find database {value} in {standby_config.universe_name}")
            database_name=database_map[value]
        if 'safe_time"' in line:
            log(f"\ndatabase_name:\t\t{database_name}\nxcluster_safe_time:\t{value}")
            if "2023-" not in value:
                uninitialized_safe_time=True
            # 2023-04-17 17:54:33.060186
            datetime_obj = datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S.%f')
            database_safe_time_map[database_name] = datetime_obj

    return uninitialized_safe_time, database_safe_time_map

def get_xcluster_estimated_data_loss(args):
    log(f"Getting estimated data loss from {standby_config.universe_name}")
    database_map = get_databases(standby_config)
    xcluster_safe_time = run_yb_admin(standby_config, "get_xcluster_estimated_data_loss")
    for line in xcluster_safe_time:
        value = line.split('":')
        if len(value) > 1:
            value = value[1].strip().replace('"','').replace(',','')
        if 'namespace_id"' in line:
            if value not in database_map:
                raise_exception(f"Cannot find database {value} in {standby_config.universe_name}")
            log(f"\nnamespace_id:\t\t{database_map[value]}")
        if 'data_loss_sec"' in line:
            log(f"data_loss_sec:\t\t{value}")

    log("\n"+Color.GREEN+"Successfully got estimated data loss")

def get_xcluster_safe_time(args):
    while True:
        current_time = datetime.datetime.utcnow()
        log(f"Current time(UTC):\t\t{current_time.strftime('%Y-%m-%d %H:%M:%S.%f')}")
        uninitialized_safe_time, database_safe_time_map = get_xcluster_safe_time_int()
        if not uninitialized_safe_time:
            break
        log(Color.YELLOW+"Some xcluster_safe_time are not initialized. Waiting...\n")
        time.sleep(2)

    if len(database_safe_time_map):
        min_datetime_obj = min(database_safe_time_map.values())
        lag = 0
        if current_time > min_datetime_obj:
            lag = current_time - min_datetime_obj
        log(f"\nMax xcluster safe time lag: {lag}")

    log("\n"+Color.GREEN+"Successfully got xcluster_safe_time")

    return database_safe_time_map

def is_standy_role(config: UniverseConfig):
    result = http_get(f"{config.master_web_server_map[0]}xcluster-config", config.ca_cert_path)
    return "role: STANDBY" in result

def set_standby_role(args):
    log(f"Setting {standby_config.universe_name} to STANDBY")
    reload_universe_roles(standby_config)
    if standby_config.role == "STANDBY":
        log(Color.GREEN+"Already in STANDBY role")
        return

    run_yb_admin(standby_config, "change_xcluster_role STANDBY")
    standby_config.role = "STANDBY"
    write_config_file()
    # Wait for async processing
    time.sleep(2)
    log(Color.GREEN+"Successfully set role to STANDBY")

    database_safe_time_map = get_xcluster_safe_time(args)
    create_snapshot_schedule_if_needed(standby_config, database_safe_time_map.keys())

def set_active_role(args):
    log(f"Setting {standby_config.universe_name} to ACTIVE")
    reload_universe_roles(standby_config)

    if standby_config.role == "ACTIVE":
        log(Color.GREEN+"Already in ACTIVE role")
        return

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
    log(f"Getting tables for database(s) {wrap_color(Color.YELLOW, ','.join(databases))} from {wrap_color(Color.YELLOW, primary_config.universe_name)}")
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
    log(f"Bootstrapping {len(table_ids)} tables...")

    result = run_yb_admin(primary_config, "bootstrap_cdc_producer "+','.join(table_ids))
    bootstrap_ids = []
    for line in result:
        bootstrap_ids.append(line.split(':')[-1].strip())

    log_to_file(bootstrap_ids)
    return bootstrap_ids

def bootstrap_databases(args):
    if bootstrap_info.initialized:
        raise_exception("There is already an available bootstrap. Run setup_replication_with_bootstrap command")

    if len(args) != 1:
        print(len(args))
        print(args)
        databases_str = input("Please provide a CSV list of database names to bootstrap: ")
    else:
        databases_str = args[0]

    databases = databases_str.split(',')

    create_snapshot_schedule_if_needed(primary_config, databases)
    table_ids = get_table_ids(databases)

    if len(table_ids) == 0:
        raise_exception("No tables found")

    bootstrap_ids = bootstrap_tables(table_ids)

    bootstrap_info.databses = databases
    bootstrap_info.table_ids = table_ids
    bootstrap_info.bootstrap_ids = bootstrap_ids
    bootstrap_info.initialized = True
    write_config_file()

    log(Color.GREEN+"Successfully bootstrapped databases. Run setup_replication_with_bootstrap command to complete setup")

def clear_bootstrap_from_config():
    bootstrap_info.initialized = False
    bootstrap_info.databses = []
    bootstrap_info.table_ids = []
    bootstrap_info.bootstrap_ids = []

    write_config_file()

def clear_bootstrap(args):
    if not bootstrap_info.initialized:
        log(Color.GREEN+"No pending bootstraps to clear")
        return

    log(f"Deleting {len(bootstrap_info.bootstrap_ids)} streams")
    for bootstrap in bootstrap_info.bootstrap_ids:
        delete_cdc_streams(bootstrap)

    clear_bootstrap_from_config()

    log(Color.GREEN+"Successfully cleared bootstrap")

def ensure_no_replication_in_progress():
    replication_name, stream_count, role = get_replication_info_int()
    if replication_name != "":
        raise_exception(f"Replication {Color.YELLOW}{replication_name}{Color.RED} already in progress."\
                        " To add more tables to an existing replication, run add_table command")

def setup_replication_with_bootstrap(args):
    ensure_no_replication_in_progress()

    if not bootstrap_info.initialized:
        bootstrap_databases(args)

    log(f"Setting up replication from {primary_config.universe_name} to {standby_config.universe_name} with bootstrap")

    result = run_yb_admin(standby_config, f"setup_universe_replication {primary_config.universe_uuid}_repl {primary_config.master_addresses} {','.join(bootstrap_info.table_ids)} {','.join(bootstrap_info.bootstrap_ids)}")
    log('\n'.join(result))

    create_snapshot_schedule_if_needed(standby_config, bootstrap_info.databses)
    clear_bootstrap_from_config()
    set_standby_role(args)

    sync_portal(args)

    log(Color.GREEN+"Successfully setup replication")

def setup_replication(args):
    if bootstrap_info.initialized:
        raise_exception("There is already an available bootstrap. Run setup_replication_with_bootstrap command")
    ensure_no_replication_in_progress()

    log(f"Setting up replication from {primary_config.universe_name} to {standby_config.universe_name} without bootstrap")

    if len(args) != 1:
        databases_str = input("Please provide a CSV list of database names to bootstrap: ")
    else:
        databases_str = args[0]

    databases = databases_str.split(',')
    create_snapshot_schedule_if_needed(primary_config, databases)
    create_snapshot_schedule_if_needed(standby_config, databases)

    table_ids = get_table_ids(databases)

    if len(table_ids) == 0:
        raise_exception("No tables found")

    result = run_yb_admin(standby_config, f"setup_universe_replication {primary_config.universe_uuid}_repl {primary_config.master_addresses} {','.join(table_ids)}")
    log('\n'.join(result))

    set_standby_role(args)
    sync_portal(args)

    log(Color.GREEN+"Successfully setup replication")


def delete_replication(args):
    replication_name, stream_count, role = get_replication_info_int()
    if replication_name == "" or stream_count == 0:
        raise_exception("No replication in progress")

    log(f"Deleting replication {wrap_color(Color.YELLOW,replication_name)} from {wrap_color(Color.YELLOW,primary_config.universe_name)} to {wrap_color(Color.YELLOW,standby_config.universe_name)}")
    result = run_yb_admin(standby_config, f"delete_universe_replication {primary_config.universe_uuid}_{replication_name}")
    log('\n'.join(result))
    sync_portal(args)
    log(Color.GREEN+"Successfully deleted replication")

def pause_replication(args):
    replication_name, stream_count, role = get_replication_info_int()
    log(f"Pausing replication from {primary_config.universe_name} to {standby_config.universe_name}")
    result = run_yb_admin(standby_config, f"set_universe_replication_enabled {primary_config.universe_uuid}_{replication_name} 0")
    log('\n'.join(result))
    log(Color.GREEN+"Successfully paused replication")
    sync_portal(args)

def resume_replication(args):
    replication_name, stream_count, role = get_replication_info_int()
    log(f"Resuming replication from {primary_config.universe_name} to {standby_config.universe_name}")
    result = run_yb_admin(standby_config, f"set_universe_replication_enabled {primary_config.universe_uuid}_{replication_name} 1")
    log('\n'.join(result))
    log(Color.GREEN+"Successfully resumed replication")
    sync_portal(args)

def swap_universe_configs(args):
    log(f"Swapping Primay and Standby universes")
    global standby_config, primary_config
    temp = standby_config
    standby_config = primary_config
    primary_config = temp

    write_config_file()
    print_header()

def wait_for_xcluster_safe_time_to_catchup():
    current_time = datetime.datetime.utcnow()
    while True:
        time.sleep(1)
        uninitialized_safe_time, database_safe_time_map = get_xcluster_safe_time_int()
        if len(database_safe_time_map) == 0:
            raise_exception("No xcluster_safe_time found")
        if not uninitialized_safe_time:
            min_datetime_obj = min(database_safe_time_map.values())
            if min_datetime_obj > current_time:
                break

        log(Color.YELLOW+f"Waiting for xcluster_safe_time to catch up to {current_time.strftime('%Y-%m-%d %H:%M:%S.%f ...')}\n")

    return database_safe_time_map

def get_databases(config: UniverseConfig):
    lines = run_yb_admin(config, "list_namespaces")
    lines = '\n'.join(lines).split('\n')
    database_map = {}
    for line in lines:
        pattern = f"(\w+) (\w+) (?:ysql|ycql) .* (?:true|false)$"
        re_match = re.search(pattern, line)
        if re_match:
            database_map[re_match.group(2)] = re_match.group(1)
    return database_map

def planned_failover(args):
    log(f"Performing a planned failover from {primary_config.universe_name} to {standby_config.universe_name}")
    replication_name, stream_count, role = get_replication_info_int()
    if replication_name == "" or stream_count == 0:
        raise_exception("No replication in progress")

    # In 2.18 this can be replaces with setting primary to STANBY role
    if not is_input_yes("Has the workload been stopped"):
        log(Color.YELLOW+"Planned failover abandoned")
        return

    wait_for_replication_drain(args)
    database_safe_time_map = wait_for_xcluster_safe_time_to_catchup()

    set_active_role(args)
    delete_replication(args)
    swap_universe_configs(args)
    setup_replication_with_bootstrap([','.join(database_safe_time_map.keys())])

    log(Color.GREEN+f"Successfully failed over from {Color.YELLOW}{standby_config.universe_name}{Color.GREEN} to {Color.YELLOW}{primary_config.universe_name}")

def unplanned_failover(args):
    log(f"Performing a unplanned failover from {primary_config.universe_name} to {standby_config.universe_name}")
    pause_replication(args)
    # Wait for async processing
    time.sleep(1)

    get_xcluster_estimated_data_loss(args)
    current_time = datetime.datetime.utcnow()
    log(f"Current time(UTC):\t\t{current_time.strftime('%Y-%m-%d %H:%M:%S.%f')}")
    uninitialized_safe_time, database_safe_time_map = get_xcluster_safe_time_int()
    if uninitialized_safe_time:
        raise_exception("UnInitialized xcluster safe time found. Cannot proceed with failover.")

    if not is_input_yes(f"Any data written to the {primary_config.universe_name} after these times will be lost. Are you sure you want to proceed"):
        log(Color.YELLOW+"Planned failover abandoned")
        return

    snapshot_info = get_snapshot_info(standby_config)

    log("Restoring databases to xcluster safe time")
    for database in database_safe_time_map.keys():
        if database not in snapshot_info:
            raise_exception(f"Snapshot not found for database {database}. Aborting failover")
        restore_to_point_in_time(standby_config, database, snapshot_info[database], database_safe_time_map[database])

    set_active_role(args)
    delete_replication(args)
    swap_universe_configs(args)

    log(Color.YELLOW+f"\nOnce {standby_config.universe_name} comes back online drop its database and recreate the database schema. Then use YBA to setup replication with backup and restore. After it completes run set_standby_role command\n")

    log(Color.GREEN+f"Successfully failed over from {Color.YELLOW}{standby_config.universe_name}{Color.GREEN} to {Color.YELLOW}{primary_config.universe_name}")

def reload_universe_roles(config: UniverseConfig):
    if is_standy_role(config):
        config.role = "STANDBY"
    else:
        config.role = "ACTIVE"

def reload_roles_int(args):
    reload_universe_roles(primary_config)
    reload_universe_roles(standby_config)

    write_config_file()

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

    return replication_name, stream_count, role

def get_replication_info_int():
    result = http_get(f"{standby_config.master_web_server_map[0]}xcluster-config", standby_config.ca_cert_path)
    return extract_consumer_registry(result)

def get_replication_info(args):
    log("Getting current replication info")
    replication_name, stream_count, role = get_replication_info_int()

    if replication_name == "" or stream_count == 0:
        log(Color.YELLOW+"No replication in progress")
        return

    log(f"{Color.GREEN}Found replication group {Color.YELLOW}{replication_name}{Color.GREEN} with {Color.YELLOW}{stream_count}{Color.GREEN} tables")
    if role != "STANDBY":
        log(f"{Color.RED}STANDBY role has not been set on {Color.RESET}{standby_config.universe_name}{Color.RED}. Please run set_standby_role command")

def get_snapshot_info(config: UniverseConfig):
    result = run_yb_admin(config, "list_snapshot_schedules")
    json_data = json.loads(''.join(result))

    database_schedules = {}
    for schedule in json_data["schedules"]:
        schedule_id = schedule["id"]
        db_name = schedule["options"]["filter"].split('.')[-1]
        if db_name not in database_schedules:
            database_schedules[db_name] = []
        database_schedules[db_name] = schedule_id

    return database_schedules

def create_snapshot_schedule(config: UniverseConfig, database_name):
    log(f"Setting up PITR snapshot schedule for {wrap_color(Color.YELLOW, database_name)} on {wrap_color(Color.YELLOW, config.universe_name)}")
    log_to_file(run_yb_admin(config, f"create_snapshot_schedule 1440 10080 ysql.{database_name}"))
    log(Color.GREEN+"Successfully created PITR snapshot schedule")

def create_snapshot_schedule_if_needed(config: UniverseConfig, databases):
    database_schedules = get_snapshot_info(config)
    for database_name in databases:
        if  database_name not in database_schedules:
            create_snapshot_schedule(config, database_name)

def delete_snapshot_schedule(config: UniverseConfig, schedule_id):
    log(run_yb_admin(config, f"delete_snapshot_schedule {schedule_id}"))

def list_snapshot_schedules_for_iniverse(config: UniverseConfig):
    log(f"Listing snapshot schedules for {Color.YELLOW}{config.universe_name}")
    database_snapshots = get_snapshot_info(config)
    for database in database_snapshots:
        log(f"Database: {database}, Schedule_id(s): {database_snapshots[database]}")

def list_snapshot_schedules(args):
    list_snapshot_schedules_for_iniverse(primary_config)
    list_snapshot_schedules_for_iniverse(standby_config)
    log(Color.GREEN+"Successfully listed snapshot schedules")

def restore_to_point_in_time(config: UniverseConfig, database: str, snapshot_id: str, restore_ime: datetime):
    restore_time_str = restore_ime.strftime('%Y-%m-%d %H:%M:%S.%f')
    log(f"Restoring {wrap_color(Color.YELLOW, database)} to {wrap_color(Color.YELLOW, restore_time_str)}")
    result = run_yb_admin(config, f'restore_snapshot_schedule {snapshot_id} "{restore_time_str}"')
    log('\n'.join(result))
    log(Color.GREEN+f"Successfully restored {database}")

def main():
    # logs latest commit and time of commit
    commit_history = run_subprocess(["git", "log", "-1"])
    log_to_file(commit_history[0], "\t" , commit_history[2])

    # Define a dictionary to map user input to functions
    function_map = {
        "configure": configure,
        "show_config":show_config,
        "validate_universes": validate_universes,
        "setup_replication" : setup_replication,
        "setup_replication_with_bootstrap" : setup_replication_with_bootstrap,
        "get_replication_info" : get_replication_info,
        "pause_replication" : pause_replication,
        "resume_replication" : resume_replication,
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
        "sync_portal" : sync_portal,
        "list_snapshot_schedules" : list_snapshot_schedules,
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
# xcluster-ctl

This tool allows you to easily manage YugabyteDB transactional xCluster deployments.
This must be run from a node that has network access ssh certificate to both universes. If you have YBA, then use the node hosting it.


# Prerequisites
- python3
- pip3
- pip3 install urllib3
- pip3 install requests


# Usage
```
python3 xcluster-ctl.py <command> [args]
commands: 
        configure
        show_config
        validate_universes
        setup_replication
        setup_replication_with_bootstrap
        get_replication_info
        set_standby_role
        set_active_role
        get_xcluster_safe_time
        planned_failover
        unplanned_failover
        add_table
        remove_table
        wait_for_replication_drain
        bootstrap_databases
        clear_bootstrap
        delete_replication
        reload_roles
        switch_universe_configs
        get_xcluster_estimated_data_loss
        pause_replication
        resume_replication
```

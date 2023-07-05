# xcluster-ctl

This tool allows you to easily manage YugabyteDB transactional xCluster deployments.
This must be run from a node that has network access ssh certificate to both universes. If you have YBA, then use the node hosting it.
Node to node encryption must be turned on.

Min supported YugabyteDB version: 2.18.0.1-b4

> **Note:** This is an unofficial script that is in active development and can break anytime. It may not support older YugabyteDB versions, and it does not have any smart retries or error handling.

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
        planned_failover
        unplanned_failover
        sync_yba
```

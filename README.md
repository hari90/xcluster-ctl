# xcluster-ctl

This tool allows you to easily manage YugabyteDB transactional xCluster deployments and perform planned and unplanned failovers.
This must be run from a node that has network access and ssh certificates to both universes. If you have YBA, then use the node hosting it.
Node to node encryption must be turned on.

Unplanned failover and setup of replication with data requires backup restore which you can follow manual instructions from [here](https://docs.yugabyte.com/preview/manage/backup-restore/snapshot-ysql) or use the YBA UI.

Min supported YugabyteDB version: 2.18.0.1-b4

> **Note:** This is an unofficial script that is in active development and can break anytime. It may not support older YugabyteDB versions, and it does not have any smart retries or error handling.

# Prerequisites
- python3
- pip3
- pip3 install urllib3
- pip3 install requests
To install the pip3 packages, you can run the following command:
```
cd pip-packages
pip3 install -r requirements.txt
```


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

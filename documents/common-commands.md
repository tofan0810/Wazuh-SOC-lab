# APPENDIX A. WAZUH DOCKER MANAGEMENT OPERATIONS

## A.1. Starting and Stopping the Wazuh System

During deployment, Wazuh is installed in a Single Node architecture using Docker Compose. The basic administration commands frequently used are as follows.

### Stopping the entire system

Before shutting down the virtual machine or performing system maintenance, gracefully stop all Wazuh services:

```bash
sudo docker compose stop
```

This command stops the Dashboard, Manager, and Indexer containers while preserving all data volumes intact.

---

### Restarting the system

Start the entire Wazuh service cluster in detached mode:

```bash
sudo docker compose up -d
```

Where:

* `up`: builds, creates, and starts containers.
* `-d`: runs containers in the background (Detached Mode).

---

### Restarting only Wazuh Manager

After modifying Rules or Decoders, restart the Manager to reload the updated configuration:

```bash
sudo docker compose restart wazuh.manager
```

---

## A.2. Checking Container Status

View running containers:

```bash
sudo docker ps
```

Check internal Wazuh processes:
```
sudo docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status
```

View all containers including stopped ones:

```bash
sudo docker ps -a
```

Expected result:

```text
single-node-wazuh.dashboard-1
single-node-wazuh.manager-1
single-node-wazuh.indexer-1
```

All should be in the state:

```text
Up
```

---

## A.3. Accessing the Wazuh Manager Container

To execute advanced administrative tasks, access the Manager container shell:

```bash
sudo docker exec -it single-node-wazuh.manager-1 bash
```

Upon execution, the terminal prompt changes to:

```bash
bash-5.2#
```

From here, you can edit Rules and Decoders, or inspect Wazuh service health.

---

## A.4. Backing Up and Editing Custom Rules

Because the Manager container does not come with text editors such as nano or vim pre-installed, Rule editing is performed on the Ubuntu host and then copied back into the container.

### Step 1. Copy the Rule file from container to host

```bash
sudo docker cp \
single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml \
~/local_rules.xml
```

Verify that the file has been copied:

```bash
ls -l ~/local_rules.xml
```

---

### Step 2. Edit the Rule file on Ubuntu

```bash
nano ~/local_rules.xml
```

or:

```bash
gedit ~/local_rules.xml
```

Add or modify Custom Rules as required.

---

### Step 3. Copy the modified file back to the container

```bash
sudo docker cp \
~/local_rules.xml \
single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
```

---

### Step 4. Re-assign permissions to the Rule file

Access the container:

```bash
sudo docker exec -it single-node-wazuh.manager-1 bash
```

Reset file ownership:

```bash
chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
```

Set file permissions:

```bash
chmod 660 /var/ossec/etc/rules/local_rules.xml
```

Verify:

```bash
ls -l /var/ossec/etc/rules/local_rules.xml
```

Expected result:

```text
-rw-rw---- 1 wazuh wazuh
```

---

## A.5. Validating Rule Syntax

After editing Rules, test syntax validity before restarting the Manager:

```bash
/var/ossec/bin/wazuh-analysisd -t
```

If the configuration is valid, the command terminates without displaying:

```text
ERROR
CRITICAL
```

If errors appear, fix the Rule syntax before proceeding.

---

## A.6. Inspecting Wazuh Manager Logs

View logs in real time:

```bash
sudo docker logs -f single-node-wazuh.manager-1
```

View the 50 most recent log lines:

```bash
sudo docker logs single-node-wazuh.manager-1 --tail 50
```

These logs help identify errors related to:

* Rules.
* Decoders.
* Active Response.
* Filebeat.
* Indexer connectivity.

---

## A.7. Inspecting Dashboard Logs

```bash
sudo docker logs single-node-wazuh.dashboard-1 --tail 50
```

Used to analyze Dashboard UI or API errors.

---

## A.8. Inspecting Indexer Logs

```bash
sudo docker logs single-node-wazuh.indexer-1 --tail 50
```

Used to analyze data storage issues, OpenSearch errors, or connectivity between Manager and Indexer.

---

## A.9. Checking Current Rule Content

Display contents of local_rules.xml:

```bash
cat /var/ossec/etc/rules/local_rules.xml
```

List all files in the Rules directory:

```bash
ls -l /var/ossec/etc/rules/
```

---

## A.10. Common Troubleshooting Procedures

### Dashboard reports 500 error

Check:

```bash
sudo docker ps
```

Ensure:

```text
single-node-wazuh.dashboard-1
single-node-wazuh.manager-1
single-node-wazuh.indexer-1
```

are all running in healthy states.

---

### Restart the entire system

```bash
sudo docker compose restart
```

---

### Verify connectivity between Manager and Indexer

```bash
sudo docker logs single-node-wazuh.manager-1 --tail 100
```

If the following string appears:

```text
Connection established
```

then the Manager has successfully connected to the Indexer.

---

## A.11. Important Paths in Wazuh

| Component | Path |
| --- | --- |
| Main Configuration | `/var/ossec/etc/ossec.conf` |
| Custom Rules | `/var/ossec/etc/rules/local_rules.xml` |
| Custom Decoders | `/var/ossec/etc/decoders/` |
| Alerts JSON | `/var/ossec/logs/alerts/alerts.json` |
| Active Response | `/var/ossec/active-response/bin/` |
| Agent Keys | `/var/ossec/etc/client.keys` |

These paths are frequently used throughout Rule authoring, Decoder development, and Active Response integration.

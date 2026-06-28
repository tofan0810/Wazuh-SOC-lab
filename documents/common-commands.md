# Appendix A. Wazuh Administration Commands on Docker

## A.1. Starting and Stopping Wazuh System

During deployment, Wazuh is installed in Single Node mode using Docker Compose. Basic administration commands frequently used are as follows.

### Stop the Entire System

Before shutting down the VM or performing system maintenance, it is recommended to stop all Wazuh services:

```bash
sudo docker compose stop
```

This command stops Dashboard, Manager, and Indexer containers but retains all data.

---

### Restart the System

Start the entire Wazuh service cluster in detached mode:

```bash
sudo docker compose up -d
```

Where:

* `up`: Initialize and run containers.
* `-d`: Run in detached mode.

---

### Restart Only Wazuh Manager

After modifying Rules or Decoders, you need to restart Manager to load the new configuration:

```bash
sudo docker compose restart wazuh.manager
```

---

## A.2. Check Container Statuses

View list of running containers:

```bash
sudo docker ps
```

Check child processes
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

all in status:

```text
Up
```

---

## A.3. Access Wazuh Manager Container

To perform advanced administration tasks, you need to access the Manager container:

```bash
sudo docker exec -it single-node-wazuh.manager-1 bash
```

After execution, the command prompt will change to:

```bash
bash-5.2#
```

From here you can edit Rules, Decoders, or check Wazuh service status.

---

## A.4. Backup and Edit Custom Rules

Since the Manager container does not have a text editor like nano or vim pre-installed, rule editing is done on the Ubuntu host then copied back to the container.

### Step 1. Copy Rule File from Container to Host

```bash
sudo docker cp \
single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml \
~/local_rules.xml
```

Check if file was copied:

```bash
ls -l ~/local_rules.xml
```

---

### Step 2. Edit Rule File on Ubuntu

```bash
nano ~/local_rules.xml
```

or:

```bash
gedit ~/local_rules.xml
```

Add or edit Custom Rules as required.

---

### Step 3. Copy Modified File Back to Container

```bash
sudo docker cp \
~/local_rules.xml \
single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
```

---

### Step 4. Reassign Permissions to Rule File

Access the container:

```bash
sudo docker exec -it single-node-wazuh.manager-1 bash
```

Reset ownership:

```bash
chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
```

Set access permissions:

```bash
chmod 660 /var/ossec/etc/rules/local_rules.xml
```

Check:

```bash
ls -l /var/ossec/etc/rules/local_rules.xml
```

Expected result:

```text
-rw-rw---- 1 wazuh wazuh
```

---

## A.5. Check Rule Validity

After modifying Rules, you need to check syntax before restarting Manager:

```bash
/var/ossec/bin/wazuh-analysisd -t
```

If configuration is valid, the command will complete without appearing:

```text
ERROR
CRITICAL
```

If errors appear, you need to edit the Rules again before continuing.

---

## A.6. Check Wazuh Manager Logs

View real-time logs:

```bash
sudo docker logs -f single-node-wazuh.manager-1
```

View last 50 log lines:

```bash
sudo docker logs single-node-wazuh.manager-1 --tail 50
```

These logs help identify errors related to:

* Rules.
* Decoders.
* Active Response.
* Filebeat.
* Indexer connection.

---

## A.7. Check Dashboard Logs

```bash
sudo docker logs single-node-wazuh.dashboard-1 --tail 50
```

Used to analyze Dashboard interface errors or API errors.

---

## A.8. Check Indexer Logs

```bash
sudo docker logs single-node-wazuh.indexer-1 --tail 50
```

Used to analyze data storage errors, OpenSearch errors, or connection errors between Manager and Indexer.

---

## A.9. Check Current Rule Content

Display content of local_rules.xml file:

```bash
cat /var/ossec/etc/rules/local_rules.xml
```

List entire Rules directory:

```bash
ls -l /var/ossec/etc/rules/
```

---

## A.10. Common Troubleshooting Operations

### Dashboard Reports Error 500

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

are all in active status.

---

### Restart Entire System

```bash
sudo docker compose restart
```

---

### Check Connection Between Manager and Indexer

```bash
sudo docker logs single-node-wazuh.manager-1 --tail 100
```

If appears:

```text
Connection established
```

then Manager has successfully connected to Indexer.

---

## A.11. Important Paths in Wazuh

| Component        | Path                                  |
| ---------------- | ------------------------------------- |
| Main config      | `/var/ossec/etc/ossec.conf`           |
| Custom Rules     | `/var/ossec/etc/rules/local_rules.xml`|
| Custom Decoders  | `/var/ossec/etc/decoders/`            |
| Alerts JSON      | `/var/ossec/logs/alerts/alerts.json`  |
| Active Response  | `/var/ossec/active-response/bin/`     |
| Agent Keys       | `/var/ossec/etc/client.keys`          |

The above paths are frequently used during Rule, Decoder, and Active Response construction.

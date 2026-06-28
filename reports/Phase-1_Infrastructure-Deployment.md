# Deploy Wazuh SIEM Infrastructure (Phase 1)

* **Project:** Research Detection Techniques and Wazuh SIEM System
* **Simulated Role:** SOC Engineer / Detection Engineer
* **Execution Environment:** Ubuntu Server v24.04 / v22.04 LTS (Running on VMware Workstation)
* **Phase 1 Objective:** Successfully deploy the central Wazuh Stack cluster (Indexer, Manager, Dashboard) using Docker Compose, optimize hardware resources, expand disk storage space, and configure secure admin password changes.

---

## I. Prepare Resources &amp; Configure Kernel Hardening

Wazuh Indexer uses a large data analysis storage core based on the OpenSearch (Java) platform. The system requires configuring the Linux kernel's virtual memory higher than default to avoid bottlenecks or process crashes during startup.

### 1. Allocate Initial VM Resources (Ubuntu Server)
* **vCPU:** 2 Cores (minimum).
* **RAM:** 4GB RAM (Minimum operational level for single-agent lab environment).
* **Storage:** Configure expansion to reach **65GB SSD** (Expand system partition to ensure log storage space and cache files).

### 2. Configure System Disk Space Expansion (Disk Partition Resizing)
After expanding hardware capacity on VMware from 40GB to 65GB, proceed to synchronize the Ubuntu operating system's logical partition to fully utilize the additional 25GB of free space using command-line tools:

```bash
# 1. Request Linux kernel to rescan sda2 partition size
sudo resizepart /dev/sda 2

# 2. Force file system to expand actual storage space
sudo resize2fs /dev/sda2
```
Check storage space again with `df -h /`, system confirms partition capacity reaches **~63GB** with large available free space (Ready to prevent disk bottlenecks).

### 3. Configure Virtual Memory Limits (Virtual Memory Tuning)

Proceed to increase the `vm.max_map_count` virtual memory parameter temporarily and configure permanent override to the system configuration file to maintain stable status after VM restart:

```bash
# Set temporary configuration in real-time
sudo sysctl -w vm.max_map_count=262144

# Write permanent configuration to system config file
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```
![Increase vm.max_map_count virtual memory parameter](images/phase1/pic1.png)

---

## II. Synchronize Docker &amp; Docker Compose Environment

To ensure encapsulation, easy configuration management, and no library conflicts with the host operating system, the entire Wazuh infrastructure is deployed via Containerization technology (Docker Engine).

### 1. Official Docker Engine Installation Command Chain

Update package list, set up secure repository (Repository GPG Key) and install Docker along with Docker Compose Plugin:

```bash
# 1. Update system and install dependency packages
sudo apt update &amp;&amp; sudo apt install -y apt-transport-https ca-certificates curl gnupg lsb-release

# 2. Set up secure Docker GPG Key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL [https://download.docker.com/linux/ubuntu/gpg](https://download.docker.com/linux/ubuntu/gpg) | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# 3. Declare Docker Repository standard according to OS version
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] [https://download.docker.com/linux/ubuntu](https://download.docker.com/linux/ubuntu) $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list &gt; /dev/null

# 4. Install official Docker components
sudo apt update &amp;&amp; sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# 5. Enable and set Docker to start with system
sudo systemctl enable docker &amp;&amp; sudo systemctl start docker
```

Check Docker Compose operational status on VM with command: `sudo docker compose version`.

![Check Docker Compose version successfully on Terminal](images/phase1/pic2.png)

---

## III. Deploy Central Wazuh Stack Cluster (Single-Node Architecture)

Use Single-node architecture configuration (suitable for research environment and small/medium enterprise labs) to consolidate all management components into one processing entity.

### 1. Synchronize Configuration Source Code from Publisher

Download pre-defined Docker configuration from Wazuh's repository:

```bash
cd ~
git clone [https://github.com/wazuh/wazuh-docker.git](https://github.com/wazuh/wazuh-docker.git) --depth=1 -b v4.14.5
cd wazuh-docker/single-node
```
### 2. Set Up System Log File Limiting Process

To prevent containers from generating infinite error log loops that unreasonably exhaust disk space when the system is abruptly shut down, proceed to add limit parameters (`logging`) to the `docker-compose.yml` file:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

---

## IV. Configure Admin Password Change (Admin Security Hardening)

To ensure maximum information security for the SOC monitoring center, the default password `SecretPassword` must be replaced with a strong password mechanism via a hash string (Hash Key).

### Step 1: Shut down system and create new password hash string

Proceed to call an intermediate container to run the OpenSearch password script to generate a secure hash:

```bash
sudo docker compose down

sudo docker run --rm -ti wazuh/wazuh-indexer:4.14.5 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh
```
*Enter new password at system prompt to receive output hash string in format:* `$2y$12$...`

### Step 2: Update internal configuration file

1. Configure new hash string into internal user management file:
```bash
nano config/wazuh_indexer/internal_users.yml
```
*Paste hash string obtained in Step 1 into the `hash` field of the `admin` account.*
2. Configure new plaintext password into `docker-compose.yml` file at `INDEXER_PASSWORD` environment parameters of both `wazuh.manager` and `wazuh.dashboard` services.

### Step 3: Apply changes into Indexer Container Core

Restart service cluster and enter inside the management container to force load security configuration:

```bash
# Start service cluster in detached mode
sudo docker compose up -d

# Access Indexer container's execution space
sudo docker exec -it single-node-wazuh.indexer-1 bash
```

When Terminal switches to `bash-5.2$` interface, execute the highest privilege loading command chain:

```bash
export INSTALLATION_DIR=/usr/share/wazuh-indexer
export CONFIG_DIR=$INSTALLATION_DIR/config
CACERT=$CONFIG_DIR/certs/root-ca.pem
KEY=$CONFIG_DIR/certs/admin-key.pem
CERT=$CONFIG_DIR/certs/admin.pem
export JAVA_HOME=/usr/share/wazuh-indexer/jdk

bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd $CONFIG_DIR/opensearch-security/ -nhnv -cacert $CACERT -cert $CERT -key $KEY -p 9200 -icl
```

System displays message: **`Done with success`** (Confirm new password configuration is officially effective across entire SIEM cluster). Type `exit` to leave container.

---

## V. Check Stability &amp; Validate Access (Validation)

Run command to check overall system health status:

```bash
sudo docker ps
```

Require all 3 entities `wazuh.indexer`, `wazuh.manager`, and `wazuh.dashboard` to maintain long-term stable status (`Up` / `healthy`).

### Validate Central Web Interface Administrative Access

* **Secure connection address:** `https://192.168.71.128` (Via static/dynamic IP of main network card `ens33` connected to VMware's Host-Only/NAT network).
* **New authentication credentials:**
* *Username:* `admin`
* *Password:* `<NEWLY_SET_PASSWORD>`

![Wazuh Dashboard Login Interface displayed in browser](images/phase1/login-page.png)

![Main admin interface (Main Dashboard) after successful login with new password, system displays safe SOC overview](images/phase1/dashboard-page.png)

---

## VI. Safe System Operation &amp; Maintenance Workflow

To ensure integrity of Indexer's large database and avoid generating system junk files, VM shutdown/startup workflow is standardized as follows:

* **Before shutting down VM/VMware:** Must actively gracefully shut down services to save Java process:
```bash
sudo docker compose stop
```


*(Absolutely do not use `down -v` command unless you want to completely erase the entire lab to start over)*.
* **After restarting VM:** Activate detached mode services again to free Terminal:
```bash
sudo docker compose up -d
```



---

## VII. Next Steps Direction (Phase 2)

The central SIEM infrastructure (Wazuh Stack) is operating perfectly and ready to receive information.

**Phase 2 Deployment Plan:**

1. Start **Windows 10 (Victim)** VM, perform download and connect **Wazuh Agent** to push information flow to Ubuntu server IP `192.168.71.128`.
2. Deeply integrate **Microsoft Sysmon** auditing toolset on target machine, customize `ossec.conf` file configuration to analyze specific Event IDs in depth, prepare for simulating and detecting real-world attacks.

## References
- [Install wazuh docker container](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)

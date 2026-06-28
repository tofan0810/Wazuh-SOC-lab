# SIEM Solution &amp; Wazuh Architecture

## Part 1: Overview of SIEM Solutions

### 1. Definitions and Terminology Meaning

**SIEM** stands for **Security Information and Event Management**.

* **S**ecurity: Network Security.
* **I**nformation: Information.
* **E**vent: Event.
* **M**anagement: Management.

&gt; **Key Difference:** Whereas pure `Syslog` is just a solution for storing operational logs, **SIEM excels with Data Analysis capabilities to detect threats**.

### 2. Components and General Data Processing Flow of SIEM

A standard SIEM solution will process data through 5 core phases:

```
[Data Collection] → [Data Ingestion] → [Data Parsing] → [Data Analysis] → [Visualization &amp; Alerting]

```

#### **Phase 1: Data Collection**
* Collect all cybersecurity-related information from every corner of the enterprise: Hardware devices, operating systems, middleware, databases, APIs, Cloud environments (Public, Private, Hybrid), to SaaS services (Office 365, GitHub, etc.).
* Deep integration with other security solutions: Antivirus, WAF, PAM/PIM, DLP, Endpoint Protection, Threat Intelligence, Identity Protection, SOAR, SOC, etc. to create the most comprehensive view.


#### **Phase 2: Data Ingestion**
* Collected data is continuously and centrally sent to the recording system to prepare for subsequent processing steps.


#### **Phase 3: Data Parsing / Data Recording**
* Transform raw data from multiple sources, multiple different formats into a **single unified format**.
* Purpose: Eliminate inconsistencies, help management, analysis, and storage achieve optimal efficiency.


#### **Phase 4: Data Analysis – "Heart of SIEM"**
* Filter, closely examine normalized data to find abnormal behaviors or attack signs.
* Use advanced techniques: *Behavior Analysis*, *Anomaly Detection*, *Integrity Verification*, and apply *AI/Machine Learning* to predict and prevent sophisticated attacks early.


#### **Phase 5: Visualization &amp; Alerting**
* Convert complex analysis results into intuitive interfaces via Dashboards, detailed reports, and flexible alert systems.
* Help administrators and SOC/Security experts quickly respond and adjust defense strategies.



---

## Part 2: General Architecture of Wazuh

Wazuh is an open-source security platform built on a flexible modular architecture, including the following main components:

### 1. Wazuh Agent (Collection Component)

* **Location:** Installed directly on endpoints that need monitoring (Windows, Linux, macOS, Cloud environments or IT infrastructure devices).
* **Function:** Collect network security status data from the server/application, **encrypt this data** and send it securely to Wazuh Manager.

### 2. Wazuh Manager (Central Brain)

* **Function:** Receive, record, and analyze security information events sent from Agents to detect threat signs, while coordinating defense responses (Cyber Kill Chain).
* **Scalability:** Supports **Clustering (Worker Node Clusters)**, allowing flexible addition/removal of nodes to handle massive log volumes from large-scale systems without bottlenecks.

### 3. Wazuh Indexer (Storage &amp; Search Engine)

* **Function:** Store, index, and support ultra-fast search of processed data.
* **Performance &amp; Security:** Allows multi-node configuration to optimize queries, increase search speed and ensure data integrity via **Data Replication** mechanism.

### 4. Wazuh Dashboard (Visual Interface)

* **Function:** Provide a graphical user interface (GUI) for users to visualize all log data, manage alerts, export reports, and monitor compliance with security standards.
* **Extensions:** Provide many useful add-ons and plugins to help optimize operational workflows for parsing and incident response experts.

---

## Summary of Lessons Learned

* **SIEM** is a closed-loop process from **Collection → Normalization → Advanced Behavior Analysis → Intuitive Alerting**.
* **Wazuh** implements this SIEM model with distributed architecture: **Agent (Collection) → Manager (Analysis/Coordination) → Indexer (Storage/Indexing) → Dashboard (Visualization)**. Thanks to modular architecture and clustering capabilities, Wazuh can scale infinitely and easily integrate with an enterprise's security ecosystem.

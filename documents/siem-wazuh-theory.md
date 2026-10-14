# **SIEM** SOLUTIONS AND **WAZUH** ARCHITECTURE

## PART 1: OVERVIEW OF SIEM SOLUTIONS

### 1. Definition and Terminology

**SIEM** stands for **Security Information and Event Management**.

* **S**ecurity
* **I**nformation
* **E**vent
* **M**anagement

> **Core Difference:** While plain `Syslog` functions solely as a passive storage mechanism for operational event logs, **SIEM excels through its Data Analysis capabilities** to detect threats.

### 2. General SIEM Architecture and Data Processing Pipeline

A standard SIEM solution processes telemetry data through five core stages:

```
[Data Collection] ──> [Data Ingestion] ──> [Data Parsing] ──> [Data Analysis] ──> [Visualization & Alerting]
```

#### **Stage 1: Data Collection**
* Ingests cybersecurity-relevant telemetry across the entire enterprise estate: hardware appliances, operating systems, middleware, databases, APIs, cloud environments (Public, Private, Hybrid), and SaaS platforms (Office 365, GitHub, etc.).
* Deeply integrates with peripheral security solutions: Antivirus, WAF, PAM/PIM, DLP, Endpoint Protection, Threat Intelligence, Identity Protection, SOAR, SOC tools to construct holistic situational awareness.

#### **Stage 2: Data Ingestion**
* Ingested telemetry is continuously streamed and aggregated into central recording ingestion buffers for downstream processing pipelines.

#### **Stage 3: Data Parsing / Normalization**
* Transforms disparate, heterogeneous raw logs into a **single unified data format**.
* Objective: Eliminates schema inconsistencies to enable optimal query performance, storage compression, and correlation efficiency.

#### **Stage 4: Data Analysis - The "Brain" of SIEM**
* Inspects and correlates parsed telemetry to uncover anomalies, indicators of compromise (IOCs), and cyber attacks.
* Employs advanced techniques: *Behavioral Analysis*, *Anomaly Detection*, *File Integrity Monitoring*, and *Machine Learning / AI* models to detect and mitigate multi-stage stealth attacks.

#### **Stage 5: Visualization & Alerting**
* Synthesizes complex analytical findings into interactive Dashboards, compliance reports, and flexible alerting channels.
* Empowers security analysts and SOC teams to triage alerts rapidly and fine-tune threat mitigation postures.

---

## PART 2: WAZUH ARCHITECTURAL OVERVIEW

Wazuh is an open-source security platform architected around a modular and extensible micro-engine framework, comprising the following primary components:

### 1. Wazuh Agent (Collection Tier)

* **Placement:** Installed directly on monitored endpoints (Windows, Linux, macOS, cloud instances, or containerized environments).
* **Role:** Gathers system events, integrity events, and security telemetry, **encrypts the payload**, and streams it securely to the Wazuh Manager.

### 2. Wazuh Manager (Central Analysis Engine)

* **Role:** Ingests, normalizes (Decoders), and correlates (Rules engine) incoming telemetry from agents to detect threats and trigger defensive countermeasures (Active Response, Kill Chain disruption).
* **Scalability:** Supports **Clustering (Master/Worker cluster topology)**, allowing horizontal scaling of worker nodes to ingest and analyze massive log volumes without bottlenecks.

### 3. Wazuh Indexer (Search & Storage Tier)

* **Role:** Stores, indexes, and delivers near real-time full-text search across all enriched security events.
* **Performance & High Availability:** Based on OpenSearch; supports multi-node clustering with **Data Replication** and sharding to guarantee resilience, fast analytical retrieval, and data durability.

### 4. Wazuh Dashboard (Visualization Tier)

* **Role:** Provides an interactive web-based graphical user interface (GUI) for visualizing threat data, tracking SIEM alerts, managing policies, generating reports, and auditing compliance frameworks (PCI-DSS, NIST 800-53, MITRE ATT&CK).
* **Extensibility:** Accommodates plugins and custom visualizations to streamline daily triage for security analysts and incident responders.

---

## SUMMARY

* **SIEM** represents an end-to-end closed-loop pipeline: **Collection -> Parsing & Normalization -> Advanced Behavioral Correlation -> Visual Alerting**.
* **Wazuh** realizes this model through a distributed architecture: **Agent** (Collection) $\rightarrow$ **Manager** (Analysis/Orchestration) $\rightarrow$ **Indexer** (Storage/Indexing) $\rightarrow$ **Dashboard** (Visualization). Through modular design and cluster scalability, Wazuh scales horizontally and integrates seamlessly into enterprise security ecosystems.
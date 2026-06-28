# Fundamentals of SMB and RDP

## 1. SMB Protocol

SMB is a network protocol developed by Microsoft to support resource sharing in Windows environments such as files, folders, printers, and other network services.

SMB operates primarily on TCP port 445 and allows users to access remote resources via Windows account authentication.

In enterprise environments, SMB is commonly used to:

* Share common folders.
* Access file servers.
* Manage resources in the internal network.

Due to using Windows account authentication, SMB is often a target of Brute Force attacks to guess usernames and passwords.

---

## 2. RDP Protocol (Remote Desktop Protocol)

RDP is a remote desktop control protocol developed by Microsoft, allowing users to access and interact directly with the Windows desktop interface over the network.

RDP operates by default on TCP port 3389.

Key features of RDP:

* Remote computer control.
* Supports system administration.
* Supports remote work.

Because it provides direct access to the system, RDP is one of the services frequently targeted by Brute Force attacks in enterprise environments.

According to MITRE ATT&amp;CK, the behavior of scanning and trying multiple consecutive passwords on RDP falls under technique T1110 – Brute Force.

---

## 3. Comparison between SMB and RDP

| Criteria                          | SMB                  | RDP                       |
| --------------------------------- | -------------------- | ------------------------- |
| Purpose                           | Resource sharing     | Remote computer control   |
| Default port                      | TCP 445              | TCP 3389                  |
| Access permissions                | File, Folder, Printer| Entire Desktop            |
| Danger level when compromised     | Medium               | High                      |
| Frequently Brute Forced           | Yes                  | Very common               |
| Appearance level in enterprises   | High                 | Very high                 |

Within the scope of this project, the RDP protocol is chosen to simulate Brute Force attacks because it is one of the most common forms of attack targeting Windows systems in real-world environments.

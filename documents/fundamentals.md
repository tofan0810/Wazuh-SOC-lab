# Theoretical Fundamentals of SMB and RDP

## 1. SMB (Server Message Block) Protocol

SMB is a network sharing protocol developed by Microsoft to facilitate the sharing of resources such as files, directories, printers, and other network services in Windows environments.

SMB operates primarily over TCP port 445 and allows users to access remote resources via Windows account authentication mechanisms.

In enterprise environments, SMB is commonly utilized for:

* Shared folder distribution.
* File Server access.
* Local network resource management.

Because it relies on Windows account authentication mechanisms, SMB is frequently targeted by brute force attacks aiming to guess usernames and passwords.

---

## 2. RDP (Remote Desktop Protocol)

RDP is a proprietary protocol developed by Microsoft that provides a user with a graphical interface to connect to and control another computer over a network.

RDP operates by default over TCP port 3389.

Core use cases of RDP:

* Remote desktop control.
* System administration and support.
* Remote workforce access.

Because it grants interactive graphical access directly into the operating system, RDP is one of the most frequently targeted services for brute force attacks across enterprise networks.

According to MITRE ATT&CK, the behavior of repeatedly guessing credentials against RDP belongs to technique T1110 – Brute Force.

---

## 3. Comparison Between SMB and RDP

| Criteria | SMB | RDP |
| --- | --- | --- |
| Primary Purpose | Resource and file sharing | Remote desktop administration |
| Default Port | TCP 445 | TCP 3389 |
| Access Level Granted | File, Folder, Printer | Full Interactive Desktop Session |
| Impact Level If Compromised | Medium | High |
| Susceptibility to Brute Force | Yes | Very High / Frequent |
| Enterprise Prevalence | High | Very High |

Within the scope of this project, RDP was selected for simulating brute force attacks because it represents one of the most prevalent real-world attack vectors against Windows endpoints.

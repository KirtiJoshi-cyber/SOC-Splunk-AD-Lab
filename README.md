# 🛡️ SOC Home Lab – Splunk SIEM | Active Directory | Brute Force Detection

![Lab Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![SIEM](https://img.shields.io/badge/SIEM-Splunk-orange)
![Platform](https://img.shields.io/badge/Platform-VMware-blue)
![ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)

## 📌 Overview

A fully functional SOC home lab built to simulate real-world threat detection and incident response workflows. The lab replicates a small enterprise environment with Active Directory, endpoint telemetry via Sysmon, and centralized log monitoring through Splunk Enterprise SIEM.

Attacks were simulated from a Kali Linux machine, with brute force attempts generating alerts in Splunk — mimicking the day-to-day work of a SOC Analyst in an MSSP environment.

---

## 🖥️ Lab Architecture

```
┌─────────────────┐        ┌──────────────────────┐        ┌───────────────────┐
│   Kali Linux    │──────▶ │  Windows Server 2019  │──────▶ │                   │
│  (Attacker)     │        │  (Active Directory /  │        │  Splunk Enterprise│
│                 │        │   Domain Controller)  │        │      SIEM         │
└─────────────────┘        └──────────────────────┘        │                   │
                                                            │  - Dashboards     │
                           ┌──────────────────────┐        │  - Alerts         │
                           │   Windows 10          │──────▶ │  - SPL Queries    │
                           │   (Endpoint / Target) │        │                   │
                           │   + Sysmon installed  │        └───────────────────┘
                           └──────────────────────┘
                                     │
                            Splunk Universal Forwarder
                            forwards logs to SIEM
```

---

## ⚙️ Technologies Used

| Component | Tool / Version |
|-----------|---------------|
| SIEM | Splunk Enterprise |
| Log Forwarding | Splunk Universal Forwarder |
| Endpoint Telemetry | Sysmon (SwiftOnSecurity config) |
| Virtualization | VMware Workstation |
| Identity & Auth | Active Directory (Windows Server 2019) |
| Attacker Machine | Kali Linux |
| Attack Tools | Crowbar / Hydra (Brute Force) |

---

## 🎯 Objectives

- ✅ Centralize Windows event logs from multiple machines into Splunk
- ✅ Monitor and alert on authentication activity (success & failure)
- ✅ Detect brute-force attacks in real time using custom SPL alerts
- ✅ Monitor process creation and network connections via Sysmon
- ✅ Simulate real attacker behavior from Kali Linux
- ✅ Map detections to MITRE ATT&CK framework

---

## 🔍 Detection Use Cases

### 1. 🔐 Authentication Monitoring

Monitored Windows Security Event logs for login activity across the domain.

| Event ID | Description |
|----------|-------------|
| 4624 | Successful Login |
| 4625 | Failed Login Attempt |

**SPL Query – Failed Login Detection:**
```spl
index=endpoint EventCode=4625
| stats count by Account_Name, IpAddress, _time
| where count > 3
| table _time, Account_Name, IpAddress, count
```

---

### 2. 🚨 Brute Force Detection (T1110)

Simulated a brute force attack from Kali Linux targeting a Windows domain account. A Splunk alert was configured to trigger when suspicious login patterns were detected.

**Alert Threshold:**
- Failed logins **> 5**
- Within a **2-minute** window
- From the **same source IP**

**SPL Query – Brute Force Alert:**
```spl
index=endpoint EventCode=4625
| bucket _time span=2m
| stats count by _time, IpAddress, Account_Name
| where count > 5
| sort -count
```

**Result:** Alert successfully triggered during simulated Kali brute force attack.

---

### 3. 🧠 Sysmon Endpoint Monitoring

Deployed Sysmon on Windows 10 endpoint to gain deeper visibility into process execution and network activity.

| Sysmon Event ID | Description |
|----------------|-------------|
| Event ID 1 | Process Creation |
| Event ID 3 | Network Connection |

**SPL Query – Suspicious Process Creation:**
```spl
index=endpoint source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time, Computer, User, CommandLine, ParentCommandLine
| sort -_time
```

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Detection |
|--------|-------------|----------------|-----------|
| Credential Access | T1110 | Brute Force | EventCode 4625 alert |
| Execution | T1059 | Command & Scripting Interpreter | Sysmon Event ID 1 |
| Discovery | T1087 | Account Discovery | AD enumeration logs |

---

## 📊 Splunk Dashboards

> 📸 *Screenshots coming soon — see `/screenshots` folder*

Dashboards built in Splunk:
- **Authentication Overview** – Login success vs failure over time
- **Brute Force Detector** – Real-time alert panel with source IP and targeted accounts
- **Sysmon Process Monitor** – Process creation timeline per host

---

## 🔑 Key Skills Demonstrated

- ✅ SIEM deployment and configuration (Splunk Enterprise)
- ✅ Log ingestion via Universal Forwarder
- ✅ SPL (Search Processing Language) query development
- ✅ Detection rule engineering and alert tuning
- ✅ Active Directory setup and domain configuration
- ✅ Sysmon deployment and endpoint telemetry
- ✅ Attack simulation (brute force from Kali Linux)
- ✅ MITRE ATT&CK framework mapping
- ✅ Threat hunting and false positive reduction

---

## 📁 Repository Structure

```
SOC-Home-Lab/
│
├── README.md
├── screenshots/
│   ├── splunk-dashboard.png
│   ├── brute-force-alert.png
│   └── sysmon-events.png
├── spl-queries/
│   ├── failed-login-detection.spl
│   ├── brute-force-alert.spl
│   └── sysmon-process-monitor.spl
└── setup-notes/
    ├── splunk-install.md
    └── sysmon-config.md
```

---

## 👤 Author

**Kirti Joshi**
SOC Analyst | 2 Years MSSP Experience | London, ON, Canada
[LinkedIn](https://www.linkedin.com/in/kirti-joshi-2084501b4/) • [Email](mailto:kirtij1303@gmail.com)

---

## 📌 Related Projects

- 🔧 SOC Defense Automation – Wazuh + pfSense + TheHive integration for automated alert ingestion
- 🖥️ Hyper-V Virtualization Lab – Secure virtual infrastructure with VLAN segmentation and NIC teaming

# 🏗️ Lab Architecture

## Network Overview

This lab simulates a small enterprise environment with three virtual machines connected on an internal NAT network, forwarding logs to a centralized Splunk SIEM.

---

## Network Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        VMware NAT Network                        │
│                                                                  │
│  ┌──────────────┐     ┌───────────────────┐   ┌──────────────┐ │
│  │  Kali Linux  │────▶│  Windows Server   │   │  Windows 10  │ │
│  │  (Attacker)  │     │  2019             │   │  (Endpoint)  │ │
│  │              │     │  - Active Dir.    │   │  - Sysmon    │ │
│  │  Tools:      │     │  - Domain Ctrl.   │   │  - Splunk    │ │
│  │  Crowbar     │     │  - Splunk Fwd.    │   │    Forwarder │ │
│  │  Hydra       │     │                   │   │              │ │
│  └──────────────┘     └───────────────────┘   └──────────────┘ │
│                                │                      │         │
│                                └──────────┬───────────┘         │
│                                           │                     │
│                                           ▼                     │
│                              ┌─────────────────────┐           │
│                              │   Splunk Enterprise  │           │
│                              │       SIEM           │           │
│                              │  - Dashboards        │           │
│                              │  - Alerts            │           │
│                              │  - SPL Queries       │           │
│                              └─────────────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Virtual Machines

| Machine | OS | Role | Key Software |
|--------|----|------|-------------|
| Kali Linux | Kali Linux 2023 | Attacker | Crowbar, Hydra, Nmap |
| Windows Server | Windows Server 2019 | Domain Controller | Active Directory, Splunk Universal Forwarder |
| Windows 10 | Windows 10 Pro | Endpoint / Target | Sysmon, Splunk Universal Forwarder |
| Splunk Host | Windows / Linux | SIEM | Splunk Enterprise |

---

## Log Flow

```
Windows Server & Windows 10
        │
        │  Windows Event Logs
        │  Sysmon Logs
        ▼
Splunk Universal Forwarder
        │
        │  Port 9997 (TCP)
        ▼
Splunk Enterprise (Indexer)
        │
        │  Indexed & Searchable
        ▼
Dashboards / Alerts / SPL Queries
```

---

## Log Sources Collected

| Log Source | Index | Description |
|-----------|-------|-------------|
| Windows Security Events | endpoint | Login success/failure (4624, 4625) |
| Sysmon Operational | endpoint | Process creation, network connections |
| Windows System Events | endpoint | System-level activity |
| Active Directory Logs | endpoint | Authentication and privilege events |

---

## Software Installed Per Machine

### Kali Linux
- Crowbar (brute force RDP/SSH)
- Hydra (brute force tool)
- Nmap (network scanning)

### Windows Server 2019
- Active Directory Domain Services (AD DS)
- DNS Server
- Splunk Universal Forwarder
- Sysmon (SwiftOnSecurity config)

### Windows 10
- Joined to Active Directory domain
- Splunk Universal Forwarder
- Sysmon (SwiftOnSecurity config)

### Splunk Host
- Splunk Enterprise (latest version)
- Receiving port: 9997
- Custom dashboards and alert rules

---

## Key Configurations

### Sysmon Config
Used the popular **SwiftOnSecurity** Sysmon configuration for comprehensive endpoint telemetry:
- Process creation logging (Event ID 1)
- Network connection logging (Event ID 3)
- File creation logging (Event ID 11)

### Splunk Forwarder inputs.conf
```
[WinEventLog://Security]
index = endpoint
disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = endpoint
disabled = false
```

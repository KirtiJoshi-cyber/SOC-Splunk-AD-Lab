# 🗺️ MITRE ATT&CK Mapping

## Overview

All attacks simulated in this lab are mapped to the [MITRE ATT&CK Framework](https://attack.mitre.org/) — the industry standard for categorizing adversary tactics, techniques, and procedures (TTPs).

---

## ATT&CK Matrix Coverage

```
Reconnaissance → Initial Access → Execution → Persistence → 
Privilege Escalation → Defense Evasion → Credential Access → 
Discovery → Lateral Movement → Collection → Exfiltration
```

**This lab covers:** Credential Access, Execution, Discovery

---

## Technique Mapping Table

| Tactic | Technique ID | Technique Name | Subtechnique | Tool Used | Detection Method |
|--------|-------------|----------------|-------------|-----------|-----------------|
| Credential Access | T1110 | Brute Force | T1110.001 – Password Guessing | Crowbar / Hydra | EventCode 4625 > 5 in 2 min |
| Credential Access | T1110 | Brute Force | T1110.003 – Password Spraying | Crowbar | EventCode 4625 multiple accounts |
| Execution | T1059 | Command & Scripting Interpreter | T1059.001 – PowerShell | PowerShell | Sysmon Event ID 1 |
| Discovery | T1087 | Account Discovery | T1087.002 – Domain Account | Net commands | Sysmon Event ID 1 CommandLine |
| Discovery | T1018 | Remote System Discovery | — | Nmap | Sysmon Event ID 3 Network Conn. |

---

## Detailed Detection Breakdown

---

### T1110 – Brute Force (Credential Access)

**What was simulated:**
Brute force attack launched from Kali Linux against a Windows domain account using Crowbar/Hydra targeting RDP or SMB.

**How it was detected:**
Splunk alert triggered on multiple failed login attempts (EventCode 4625) from the same source IP within a 2-minute window.

**SPL Detection Query:**
```spl
index=endpoint EventCode=4625
| bucket _time span=2m
| stats count by _time, IpAddress, Account_Name
| where count > 5
| sort -count
```

**Alert Threshold:**
- Failed logins > 5
- Within 2 minutes
- From same source IP

**Evidence in Splunk:**
- Source IP: Kali Linux IP
- Target Account: Domain user account
- EventCode: 4625 (Failed Login)

---

### T1059.001 – PowerShell (Execution)

**What was simulated:**
PowerShell commands executed on Windows endpoint to simulate post-exploitation activity.

**How it was detected:**
Sysmon Event ID 1 (Process Creation) capturing PowerShell execution with full command line arguments.

**SPL Detection Query:**
```spl
index=endpoint source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*powershell*"
| table _time, Computer, User, CommandLine, ParentCommandLine
| sort -_time
```

**Indicators:**
- Process: powershell.exe
- Parent Process: cmd.exe or suspicious parent
- CommandLine arguments logged

---

### T1087.002 – Domain Account Discovery (Discovery)

**What was simulated:**
Running `net user /domain` and `net group /domain` commands to enumerate Active Directory accounts.

**How it was detected:**
Sysmon Event ID 1 capturing net.exe execution with domain enumeration arguments.

**SPL Detection Query:**
```spl
index=endpoint source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*net*user*domain*" OR CommandLine="*net*group*domain*"
| table _time, Computer, User, CommandLine
| sort -_time
```

---

### T1018 – Remote System Discovery (Discovery)

**What was simulated:**
Nmap scan from Kali Linux to identify live hosts and open ports on the internal network.

**How it was detected:**
Sysmon Event ID 3 (Network Connection) showing unusual outbound/inbound connection patterns.

**SPL Detection Query:**
```spl
index=endpoint source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| stats count by SourceIp, DestinationIp, DestinationPort
| where count > 10
| sort -count
```

---

## Alert Summary

| Alert Name | Technique | Severity | Status |
|-----------|-----------|----------|--------|
| Brute Force Detected | T1110 | 🔴 High | ✅ Triggered Successfully |
| PowerShell Execution | T1059.001 | 🟡 Medium | ✅ Detected via Sysmon |
| Domain Enumeration | T1087.002 | 🟡 Medium | ✅ Detected via Sysmon |
| Network Scan Detected | T1018 | 🟠 Medium-High | ✅ Detected via Sysmon |

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)
- [T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [T1087 – Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [T1018 – Remote System Discovery](https://attack.mitre.org/techniques/T1018/)

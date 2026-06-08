# SIEM Home Lab — Threat Detection & Incident Response

**Tools:** Elastic Stack 8.x | Sysmon | Winlogbeat | VirtualBox | Windows 10 | Ubuntu Server 22.04  
**Techniques Detected:** MITRE ATT&CK T1110, T1136, T1059.001, T1071  
**Author:** Toneal | Former MDDR Analyst Intern — Varonis Systems

---

## Overview
Built a fully functional SIEM environment from scratch using 
Elastic Stack to detect and investigate simulated cyberattacks. 
Deployed Sysmon on a Windows endpoint for detailed telemetry, 
configured Winlogbeat for log shipping, authored 5 custom 
detection rules, simulated real attack techniques, and produced 
professional incident reports following SOC standards.

---

## Lab Architecture
Windows 10 VM (Sysmon + Winlogbeat) → Winlogbeat → Elasticsearch → Kibana

- Windows 10 VM: Endpoint with Sysmon installed for enhanced logging
- Winlogbeat: Ships Windows event logs to Elasticsearch in near real time  
- Elasticsearch: Stores and indexes all log data
- Kibana: SIEM dashboard for searching logs and managing detection rules
- Network: All VMs on bridged adapter — Ubuntu SIEM accessible at 192.168.1.36
---

## Detection Rules Built

| # | Rule Name | Event ID | MITRE TTP |
|---|-----------|----------|-----------|
| 1 | Brute Force Login Detection | 4625 | T1110 |
| 2 | New Local User Account Created | 4720 | T1136.001 |
| 3 | Encoded PowerShell Execution | 4104 | T1059.001 |
| 4 | Suspicious Parent-Child Process | 1 | T1059.001 |
| 5 | Unusual Outbound Network Connection | 3 | T1071.001 |

---

## Attack Simulations & Investigations

| ID | Attack Simulated | Detection Method | Report |
|----|-----------------|------------------|--------|
| IR-001 | Brute Force Login | Event ID 4625 threshold rule | [View](incident-reports/IR-001-brute-force.md) |
| IR-002 | Backdoor User Creation | Event ID 4720 | [View](incident-reports/IR-002-user-account-created.md) |
| IR-003 | Encoded PowerShell C2 | Event ID 4104 Script Block | [View](incident-reports/IR-003-encoded-powershell.md) |
| IR-004 | Suspicious Process Execution | Sysmon Process Create | [View](incident-reports/IR-004-suspicious-process.md) |
| IR-005 | Outbound C2 Beacon Attempt | Sysmon Event ID 3 | [View](incident-reports/IR-005-outbound-network.md) |

---

## Key Findings & Lessons Learned

- PowerShell Script Block Logging (Event ID 4104) must be 
  explicitly enabled via registry — it is off by default
- Detection rules are only as effective as the underlying 
  logging configuration
- Sysmon with the SwiftOnSecurity ruleset provides 
  significantly better endpoint visibility than default 
  Windows logging
- MITRE ATT&CK framework provides a consistent language 
  for mapping detections to real-world threat actor behavior

---

## Tools & Technologies

| Tool | Purpose |
|------|---------|
| Elasticsearch | Log storage and indexing |
| Kibana | SIEM dashboard and detection rules |
| Winlogbeat | Log shipping from Windows to Elasticsearch |
| Sysmon | Enhanced Windows endpoint telemetry |
| VirtualBox | Virtual machine hypervisor |
| Windows 10 | Endpoint (victim machine) |
| Ubuntu Server 22.04 | SIEM server |
| MITRE ATT&CK Navigator | Threat coverage mapping |

---

## Screenshots
*See /screenshots folder for Kibana dashboard, detection 
rule configurations, and alert evidence*

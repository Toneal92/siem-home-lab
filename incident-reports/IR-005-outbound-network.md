# Incident Report — IR-005
**Date:** June 3, 2026  
**Severity:** Medium  
**Status:** Resolved (simulated)  
**Analyst:** Toneal

## Executive Summary
Unusual outbound network connections were detected from 
endpoint DESKTOP-BK5SL06. Sysmon Event ID 3 captured 
PowerShell making outbound connections to external IP 
addresses outside the local 192.168.x.x network range. 
This technique is commonly used by attackers for command 
and control communication or data exfiltration.

## Timeline
| Time | Event |
|------|-------|
| 16:04:00 | PowerShell initiated outbound connection |
| 16:04:00 | Sysmon Event ID 3 generated |
| 16:04:00 | Destination IP: 8.8.8.8 (Google DNS) |
| 16:04:00 | Connection failed - remote server unreachable |
| 16:04:05 | Event shipped to SIEM via Winlogbeat |

## Technical Findings
**Attack Technique:** Application Layer Protocol (T1071)  
**Affected System:** DESKTOP-BK5SL06  
**Process:** powershell.exe  
**Destination IP:** 8.8.8.8  
**Destination Port:** 80  
**Protocol:** HTTP  
**Event ID:** 3 (Sysmon Network Connection)  
**Total External Connections Observed:** 219  

## MITRE ATT&CK Mapping
- **Tactic:** Command and Control
- **Technique:** T1071 — Application Layer Protocol
- **Sub-technique:** T1071.001 — Web Protocols

## Root Cause
PowerShell executed a WebClient DownloadString request to 
an external IP address simulating malware beaconing to a 
command and control server. The connection failed because 
the destination was unreachable in the lab environment.

## Recommendations
1. Block outbound PowerShell network connections via firewall
2. Implement DNS filtering to block malicious domains
3. Alert on any PowerShell process making external connections
4. Use web proxy to inspect all outbound HTTP traffic
5. Implement egress filtering to allow only approved destinations

## Lessons Learned
Sysmon network connection logging provides excellent 
visibility into outbound connections. Combining process 
name with destination IP filtering creates highly effective 
detection for C2 communication attempts. Egress filtering 
would have blocked this connection entirely.

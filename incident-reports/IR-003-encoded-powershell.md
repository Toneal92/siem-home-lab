# Incident Report — IR-003
**Date:** June 2, 2026  
**Severity:** High  
**Status:** Resolved (simulated)  
**Analyst:** Toneal

## Executive Summary
Encoded PowerShell execution was detected on endpoint 
DESKTOP-BK5SL06. Event ID 4104 was triggered indicating 
PowerShell Script Block Logging captured a suspicious 
encoded command execution. This technique is commonly 
used by attackers to obfuscate malicious commands and 
evade basic detection.

## Timeline
| Time | Event |
|------|-------|
| 16:01:50 | First encoded PowerShell execution (Event ID 4104) |
| 16:02:04 | Last encoded PowerShell execution detected |
| 16:02:05 | Event ingested into SIEM via Winlogbeat |
| 16:02:05 | Detection rule triggered |

## Technical Findings
**Attack Technique:** PowerShell Encoded Command (T1059.001)  
**Affected System:** DESKTOP-BK5SL06  
**Event Provider:** Microsoft-Windows-PowerShell  
**Channel:** Microsoft-Windows-PowerShell/Operational  
**Event ID:** 4104  
**Process ID:** 6540  
**Script Block ID:** 57400ff2-ccd3-4e3b-a949-772a53a23462  
**Total Events Generated:** 8  

## MITRE ATT&CK Mapping
- **Tactic:** Execution
- **Technique:** T1059.001 — PowerShell
- **Sub-technique:** Encoded Command Execution

## Root Cause
An encoded PowerShell command was executed using the 
-EncodedCommand parameter to hide malicious code from 
basic string detection. The command attempted to download 
a remote payload from http://tust.com which failed due 
to the domain being unreachable.

## Recommendations
1. Enable PowerShell Script Block Logging on all endpoints
2. Alert on all use of -EncodedCommand parameter
3. Implement PowerShell Constrained Language Mode
4. Block PowerShell execution for non-administrative users
5. Monitor for PowerShell making outbound network connections

## Lessons Learned
PowerShell Script Block Logging must be explicitly enabled 
via registry to detect encoded command execution. Without 
this setting the attack would have gone completely 
undetected highlighting the importance of proper endpoint 
logging configuration before deploying detection rules.

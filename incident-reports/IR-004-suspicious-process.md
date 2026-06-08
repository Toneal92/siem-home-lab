# Incident Report — IR-004
**Date:** June 3, 2026  
**Severity:** High  
**Status:** Resolved (simulated)  
**Analyst:** Toneal

## Executive Summary
A suspicious PowerShell process execution was detected on 
endpoint DESKTOP-BK5SL06. Sysmon telemetry captured 
powershell.exe being spawned and creating files on the 
system. This technique is commonly used by attackers who 
have gained initial access via a malicious document or 
script and are using PowerShell for follow-on execution.

## Timeline
| Time | Event |
|------|-------|
| 15:47:39 | PowerShell process spawned (PID 1680) |
| 15:47:43 | File creation event detected |
| 15:47:43 | Event shipped to SIEM via Winlogbeat |
| 15:47:43 | Detection rule triggered |

## Technical Findings
**Attack Technique:** PowerShell Execution (T1059.001)  
**Affected System:** DESKTOP-BK5SL06  
**Affected User:** toneal  
**Process Name:** powershell.exe  
**Process ID:** 1680  
**Process Path:** C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  
**Event Action:** FileCreate  
**OS:** Windows 10.0  

## MITRE ATT&CK Mapping
- **Tactic:** Execution
- **Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell

## Root Cause
PowerShell was launched and executed commands that resulted 
in file creation activity on the endpoint. In a real attack 
this would indicate an attacker using PowerShell for 
post-exploitation activity such as downloading payloads 
dropping files or establishing persistence mechanisms.

## Recommendations
1. Restrict PowerShell execution to administrators only
2. Enable PowerShell Constrained Language Mode
3. Alert on any PowerShell process creating files
4. Implement application whitelisting via AppLocker
5. Monitor all PowerShell process spawning events via Sysmon

## Lessons Learned
Sysmon file creation events combined with process monitoring 
provide excellent visibility into PowerShell abuse. Parent 
process tracking should be enabled to identify what launched 
PowerShell in the first place.

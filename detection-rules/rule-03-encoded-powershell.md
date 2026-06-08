# Detection Rule 03 — Encoded PowerShell Execution

**MITRE ATT&CK:** T1059.001 — PowerShell  
**Tactic:** Execution  
**Severity:** High  
**Event ID:** 4104 (Script Block Logging)

## Rule Query (KQL)
event.code: "4104" and process.command_line: *encodedcommand*

## Threshold
- Count: more than 0 occurrences
- Time window: 5 minutes
- Data source: winlogbeat-*

## Why This Matters
Attackers use Base64 encoded PowerShell commands to hide 
malicious code from basic string-based detection tools. 
Legitimate administrators rarely need to use encoded 
commands making this a high confidence indicator of 
malicious activity.

## True Positive Example
Malware uses PowerShell -EncodedCommand flag to download 
and execute a second stage payload from a remote server 
while evading basic keyword detection.

## False Positive Considerations
- Some legitimate software installers use encoded commands
- SCCM and other management tools may use encoding
- Review the decoded script block text to confirm intent

## Prerequisites
PowerShell Script Block Logging must be enabled:
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

## Response Actions
1. Decode the Base64 command to see what it was doing
2. Check destination IP if a network connection followed
3. Review parent process that launched PowerShell
4. Isolate endpoint if payload was successfully downloaded
5. Search for persistence mechanisms left behind

# Detection Rule 04 — Suspicious Parent-Child Process

**MITRE ATT&CK:** T1059.001 — PowerShell  
**Tactic:** Execution  
**Severity:** High  
**Event ID:** 1 (Sysmon Process Create)

## Rule Query (KQL)
process.parent.name: "WINWORD.exe" and process.name: "powershell.exe"

## Threshold
- Count: more than 0 occurrences
- Time window: 5 minutes
- Data source: winlogbeat-*

## Why This Matters
Microsoft Word should never launch PowerShell under normal 
circumstances. This parent-child relationship is a classic 
indicator of a malicious macro embedded in an Office 
document executing a payload. This technique is used in 
phishing attacks worldwide.

## True Positive Example
A user opens a phishing email attachment disguised as an 
invoice. The Word document contains a malicious macro that 
launches PowerShell to download ransomware.

## False Positive Considerations
- Extremely rare in legitimate environments
- Some old enterprise tools may use this pattern
- Treat as high confidence malicious until proven otherwise

## Response Actions
1. Immediately isolate the affected endpoint
2. Identify the Word document that triggered the macro
3. Check what PowerShell command was executed
4. Look for any files dropped or network connections made
5. Notify user and check if they opened a suspicious email
6. Submit the document to a sandbox for analysis

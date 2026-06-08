# Detection Rule 05 — Unusual Outbound Network Connection

**MITRE ATT&CK:** T1071.001 — Web Protocols  
**Tactic:** Command and Control  
**Severity:** Medium  
**Event ID:** 3 (Sysmon Network Connection)

## Rule Query (KQL)
event.code: "3" and not destination.ip: "192.168.*"

## Threshold
- Count: more than 0 occurrences
- Time window: 5 minutes
- Data source: winlogbeat-*

## Why This Matters
Malware communicates with attacker-controlled servers 
called command and control (C2) servers to receive 
instructions and exfiltrate data. Detecting unexpected 
outbound connections from unusual processes is a key 
indicator of compromise.

## True Positive Example
PowerShell malware beacons to a C2 server every 5 minutes 
sending system information and waiting for commands from 
the attacker.

## False Positive Considerations
- Many legitimate applications make external connections
- Windows Update, browsers, antivirus all make outbound connections
- Focus on unusual processes making connections (PowerShell, cmd.exe)
- Tune by adding known-good destination IPs to exclusion list

## Response Actions
1. Identify which process made the connection
2. Look up the destination IP in threat intelligence feeds
3. Check if data was sent outbound (bytes transferred)
4. Block destination IP at firewall immediately if malicious
5. Check for persistence mechanisms and lateral movement
6. Preserve memory dump for forensic analysis

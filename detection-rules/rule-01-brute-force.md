# Detection Rule 01 — Brute Force Login Detection

**MITRE ATT&CK:** T1110 — Brute Force  
**Tactic:** Credential Access  
**Severity:** High  
**Event ID:** 4625 (Failed Logon)

## Rule Query (KQL)
event.code: "4625"

## Threshold
- Count: more than 5 occurrences
- Time window: 1 minute
- Data source: winlogbeat-*

## Why This Matters
Multiple failed login attempts in a short window indicate 
an automated brute force attack attempting to guess 
credentials. A single failed login is normal — ten in 
one minute is not.

## True Positive Example
An attacker runs a password spraying tool against a 
Windows endpoint generating dozens of Event ID 4625 
entries in seconds.

## False Positive Considerations
- User genuinely forgetting their password
- Locked out domain account repeatedly trying
- Reduce false positives by raising threshold to 10+

## Response Actions
1. Identify source IP of failed attempts
2. Check if any subsequent successful login (4624) occurred
3. Lock the targeted account if active attack confirmed
4. Block source IP at firewall if external

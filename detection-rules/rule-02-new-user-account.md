# Detection Rule 02 — New Local User Account Created

**MITRE ATT&CK:** T1136.001 — Local Account Creation  
**Tactic:** Persistence  
**Severity:** High  
**Event ID:** 4720 (User Account Created)

## Rule Query (KQL)
event.code: "4720"

## Threshold
- Count: more than 0 occurrences
- Time window: 5 minutes
- Data source: winlogbeat-*

## Why This Matters
Attackers create new local user accounts to maintain 
persistent access to a compromised machine. Any new 
account creation should be investigated immediately 
unless it was authorized by IT.

## True Positive Example
An attacker who has gained admin access creates a 
backdoor account called HackerUser to ensure continued 
access even if their initial foothold is removed.

## False Positive Considerations
- IT administrator legitimately creating a new account
- Onboarding process for a new employee
- Verify with IT before escalating

## Response Actions
1. Identify who created the account (SubjectUserName field)
2. Identify the new account name (TargetUserName field)
3. Disable the account immediately if unauthorized
4. Check for any activity performed under the new account
5. Investigate how attacker gained admin privileges

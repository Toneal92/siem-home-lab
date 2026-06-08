# Incident Report — IR-002
**Date:** April 29, 2026  
**Severity:** High  
**Status:** Resolved (simulated)  
**Analyst:** Toneal

## Executive Summary
A new user account creation event was detected on endpoint 
DESKTOP-BK5SL06. Event ID 4720 was triggered indicating a 
new local account was created. This technique is commonly 
used by attackers for persistence.

## Timeline
| Time | Event |
|------|-------|
| 03:23:06 | Account creation event generated (Event ID 4720) |
| 03:27:07 | Event shipped to SIEM via Winlogbeat |
| 03:27:07 | Detection rule triggered |
| 03:27:10 | Investigation began |

## Technical Findings
**Attack Technique:** Local Account Creation (T1136.001)  
**Affected System:** DESKTOP-BK5SL06  
**Subject Username:** MINWINPC$  
**Target Username:** HackerUser  
**Event ID:** 4720  

## MITRE ATT&CK Mapping
- **Tactic:** Persistence
- **Technique:** T1136.001 — Local Account Creation

## Root Cause
An attacker with administrator privileges created a new 
local user account to maintain persistent access to the 
compromised endpoint. This backdoor account would allow 
re-entry even if the initial access method was remediated.

## Recommendations
1. Alert on all Event ID 4720 activity immediately
2. Review all local accounts on endpoints regularly
3. Restrict account creation privileges to domain admins only
4. Audit local administrator group membership weekly
5. Implement Privileged Access Workstations for admin tasks

## Lessons Learned
The detection fired immediately on account creation giving 
analysts real time visibility into persistence attempts. 
Correlating the SubjectUserName field quickly identified 
which account performed the action.

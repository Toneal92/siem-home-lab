# Incident Report — IR-001
**Date:** May 8, 2026  
**Severity:** High  
**Status:** Resolved (simulated)  
**Analyst:** Toneal

## Executive Summary
Multiple failed login attempts were detected on endpoint 
DESKTOP-BK5SL06. Ten consecutive Event ID 4625 failures 
were observed within a one minute window indicating a 
brute force attack against local accounts.

## Timeline
| Time | Event |
|------|-------|
| 04:12:12 | First failed login attempt (Event ID 4625) |
| 04:12:39 | Tenth failed login attempt detected |
| 04:12:39 | Detection rule triggered in SIEM |
| 04:12:40 | Investigation began |

## Technical Findings
**Attack Technique:** Brute Force (T1110)  
**Affected System:** DESKTOP-BK5SL06  
**Targeted Account:** fakeuser  
**Total Failed Attempts:** 10  
**Timeframe:** Under 1 minute  
**Event ID:** 4625  

## MITRE ATT&CK Mapping
- **Tactic:** Credential Access
- **Technique:** T1110 — Brute Force

## Root Cause
An attacker simulated using an automated tool to repeatedly 
attempt logins with incorrect credentials targeting a local 
Windows account. The high volume of failures in a short 
timeframe is consistent with automated password guessing.

## Recommendations
1. Implement account lockout policy after 5 failed attempts
2. Enable MFA on all accounts
3. Alert on any account with more than 5 failed logins in 1 minute
4. Review logs for successful login after failed attempts
5. Block source IP at firewall if attack is external

## Lessons Learned
Detection rule successfully identified brute force pattern.
Consider reducing threshold to 3 attempts for faster detection.

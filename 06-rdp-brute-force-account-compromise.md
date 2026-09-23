# Incident Report — RDP Brute Force → Account Compromise

**Analyst:** Juan Soto · **Environment:** LetsDefend simulated SOC · **Alert:** SOC176 (Event ID 234) · **Severity:** Medium → escalated · **Verdict:** True Positive — successful brute force

> Educational SOC investigation on the LetsDefend training platform. All hosts and IPs are lab artifacts.

---

## Executive summary

An external IP ran an **RDP brute-force** attack against an internal host (`Matthew`, 172.16.17.148) on port 3389. After a burst of failed logins, the attacker **successfully authenticated** — turning a routine brute-force alert into a confirmed account compromise. Recommended immediate isolation of the host.

## Alert details

| Field | Value |
|---|---|
| Rule | SOC176 — RDP Brute Force Detected |
| Event time | 2024-03-07 11:44 |
| Source IP | 218.92.0.56 (external; flagged by 11 AV engines on VirusTotal) |
| Destination | 172.16.17.148 (`Matthew`), port 3389 (RDP) |
| Protocol | RDP |

## Investigation

1. **Enrichment.** The source IP is external and **flagged malicious by 11 engines on VirusTotal** — not a benign internal scanner.
2. **Traffic analysis.** Log Management showed **~15 firewall log entries** from that IP hammering `Matthew` on port 3389 in a short window — the signature of an automated brute-force.
3. **Scope.** The attacker targeted **only** `172.16.17.148`, not a spray across many hosts — a focused attempt on one machine.
4. **Did it succeed?** This is the decisive check. After the string of failed attempts, the logs showed a **successful login** using the username `Matthew` on the target host. Failed-then-successful on the same account is the pattern that confirms the brute force **worked**.

## Verdict & impact

**True Positive — successful brute force, account compromised.** The attacker gained interactive RDP access to `Matthew`. Assume the account and anything reachable from that host are compromised; interactive access enables lateral movement, credential theft and persistence.

## MITRE ATT&CK

- **T1110** — Brute Force
- **T1078 / T1078.002** — Valid Accounts (Domain Accounts)
- **T1021.001** — Remote Services: Remote Desktop Protocol
- Supporting: T1087 (Account Discovery)

## Response & recommendations

1. **Isolate `Matthew`** immediately (EDR/network) — active compromise via interactive RDP.
2. **Reset the compromised account's password** and any credentials reused elsewhere; review the account's activity after the successful login.
3. **Block** source IP 218.92.0.56 at the perimeter.
4. **Reduce exposure:** RDP should not be reachable from the internet — put it behind a VPN, enforce MFA/Network Level Authentication, and add account-lockout thresholds so a brute force can't run to completion.
5. **Hunt** for lateral movement and persistence from `Matthew` after the login timestamp.

## Lesson learned

A brute-force alert is only "medium" until you answer one question: did any attempt actually succeed? The failed-to-successful login sequence on the same account is what turns "someone tried" into "someone is in." The response — the successful authentication event — decides the severity, not the volume of failures.

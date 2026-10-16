# Incident Report — SQL Injection (UNION-based, with attempted RCE)

**Analyst:** Juan Soto · **Environment:** LetsDefend simulated SOC · **Alert:** SOC127 (Event ID 235) · **Severity:** High · **Verdict:** True Positive — attack blocked / unsuccessful

> Educational SOC investigation on the LetsDefend training platform. All hosts and IPs are lab artifacts.

---

## Executive summary

A web server (`WebServer1000`, 172.16.20.12) was targeted by an attacker (118.194.247.28, China) who **port-scanned first, then ran UNION-based SQL injection** against a query parameter. The payload went beyond data theft — it tried to chain into `information_schema` enumeration, reflected XSS, and even `xp_cmdshell` to read `/etc/passwd`. Reviewing the responses, I found **no evidence the injection returned data or executed commands**, so this closed as a True Positive that was ultimately unsuccessful — the alert was real, the attack failed.

## Alert details

| Field | Value |
|---|---|
| Rule | SOC127 — SQL Injection Detected |
| Event time | 2024-03-07 12:51 |
| Source IP | 118.194.247.28 (internet, China) |
| Destination | 172.16.20.12 (`WebServer1000`) |
| Method | GET (injection in the `douj` query parameter) |
| Device action | Allowed |

## Investigation

1. **Context first.** The same source IP appeared earlier performing a **port scan**, then pivoted to SQL injection — a recon-then-exploit sequence, not a stray request.
2. **Decode the payload.** URL-decoding the `douj` parameter revealed a stacked attack:
   `... AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1 ; EXEC xp_cmdshell('cat ../../../etc/passwd')`
   That is UNION-based SQLi (column enumeration + `information_schema`), a reflected-XSS test, **and** an `xp_cmdshell` attempt to run OS commands through the database — the attacker was probing for everything at once.
3. **Direction & intent.** Internet → internal web server; clearly malicious, not a planned test.
4. **Did it work?** This is the decision point. Across the attacker's requests the **response sizes were consistent and no injected data was reflected back** — the hallmark of a database rejecting or not evaluating the injected sub-query. A successful UNION extraction would have shown **varying response sizes** as different rows returned. It didn't. The `xp_cmdshell` call produced no command output either.

## Verdict & impact

**True Positive — malicious, but unsuccessful.** The attempt was real and hostile (and notable for reaching for RCE via `xp_cmdshell`), but the application/database did not return data or execute commands. No data exfiltration, no code execution. Closed without Tier 2 escalation, with hardening recommendations.

## MITRE ATT&CK

- **T1595** — Active Scanning (the preceding port scan)
- **T1190** — Exploit Public-Facing Application (SQL injection attempt)
- **T1552.001** — Unsecured Credentials: Credentials in Files (the `/etc/passwd` target)

## Response & recommendations

1. **Block** 118.194.247.28 at the perimeter and add to threat intel.
2. **Fix the root cause:** parameterize queries / use prepared statements; the parameter should never reach the database as raw SQL.
3. **Disable `xp_cmdshell`** on the SQL Server if it isn't required — it turns a SQLi into remote code execution.
4. **Add a WAF rule / detection** for `UNION SELECT`, `information_schema`, and `xp_cmdshell` patterns, and review whether this parameter is exposed elsewhere.

## Lesson learned

Success for SQL injection is decided by the **response**, not the firewall's "Allowed" action or a lone `200` status. Consistent response sizes with no reflected data mean the injection didn't land; varying sizes are what betray a real extraction. Judging this by the device action alone would have over-escalated a blocked attack — the same discipline that stops under-escalating a real one.

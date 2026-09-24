# SOC Analyst Portfolio — Juan Soto

Blue-team / SOC analyst focused on alert triage, log correlation and evidence-based verdicts. These are incident write-ups from **20 alert-to-closure investigations** I completed in the [LetsDefend](https://letsdefend.io) simulated SOC (95% success rate).

**Verified transcript:** https://app.letsdefend.io/user/Abbyroad
**Credentials (Credly):** https://www.credly.com/users/juan-soto.7417c7d2 — CompTIA Security+ · Blue Team Level 1 (BTL1) · Splunk Core Certified Power User · Fortinet FCF/NSE 1–2

---

## Incident write-ups

Ten curated cases spanning web exploitation, network-device CVEs, malware/macro analysis, phishing, threat hunting, brute force, SQL injection and identity/MFA. Each follows the same discipline: take the alert, decide true/false positive from **host and network evidence** (not the alert label), map to MITRE ATT&CK, and give a containment recommendation. Notably, the set includes both *successful* and *blocked/unsuccessful* attacks — because knowing the difference is the job.

| # | Case | Technique | Verdict |
|---|---|---|---|
| 01 | [SharePoint "ToolShell" Auth Bypass → RCE (CVE-2025-53770)](01-sharepoint-toolshell-CVE-2025-53770.md) | Public-facing exploit → RCE → web shell | TP · active compromise |
| 02 | [Lumma Stealer via ClickFix Phishing](02-lumma-stealer-clickfix-phishing.md) | Phishing → user execution → mshta payload | TP · successful |
| 03 | [Command Injection → Active Breach](03-command-injection-active-breach.md) | Command injection → credential access | TP · active breach |
| 04 | [Check Point Gateway File Read (CVE-2024-24919)](04-checkpoint-gateway-file-read-CVE-2024-24919.md) | Path traversal → arbitrary file read → credential exposure | TP · successful |
| 05 | [Internal Phishing → Threat-Hunt Finding](05-internal-phishing-threat-hunt.md) | Threat hunting → staged internal account compromise | Parallel host compromise |
| 06 | [RDP Brute Force → Account Compromise](06-rdp-brute-force-account-compromise.md) | Brute force → interactive RDP access | TP · account compromise |
| 07 | [PAN-OS GlobalProtect Command Injection (CVE-2024-3400)](07-panos-command-injection-CVE-2024-3400.md) | Firewall RCE via cookie → curl call-back | TP · successful |
| 08 | [SQL Injection with Attempted RCE](08-sql-injection-analysis.md) | UNION SQLi + `xp_cmdshell` attempt | TP · blocked / unsuccessful |
| 09 | [VPN Login from Unauthorized Country](09-vpn-unauthorized-country-mfa.md) | Valid creds from Vietnam → MFA held | TP · creds compromised, access blocked |
| 10 | [Malicious Office Macro → PowerShell Payload](10-malicious-macro-office-document.md) | Maldoc → PowerShell → 2nd-stage download | TP · executed, not quarantined |

## Detection Engineering (Splunk / SPL)

Beyond triaging alerts, I write the detections. See **[detections/](detections/README.md)** — Splunk SPL rules mapped to MITRE ATT&CK for the techniques above (ToolShell, ClickFix/Lumma, PAN-OS injection, web command injection, RDP brute force, SQL injection, and impossible-travel/MFA), each with tuning and false-positive notes. This is where the LetsDefend triage work turns into something a SOC can deploy.

## How I work

- **Evidence over alert metadata.** A firewall "Allowed" is not proof an attack worked; HTTP status codes, response sizes and host process/command history are. I document what I see, not what I assume.
- **Full chain, not just the indicator.** In the Lumma case, the real second-stage C2 domain was only visible on the endpoint — the alert never named it.
- **Escalate on confirmed impact.** Reconnaissance-looking alerts get checked against what the host actually executed before I set severity.
- **Hunt past the alert.** The internal-phishing email was clean on its own evidence — following what the host did next uncovered a separate, staged account compromise.

## Toolset

Splunk (SPL) · Windows Event Logs · Wireshark · VirusTotal / AbuseIPDB / URLScan · MITRE ATT&CK · Cyber Kill Chain · EDR containment · phishing & email header analysis (SPF/DKIM/DMARC).

---

*Write-ups are of my own investigations on the LetsDefend training platform; hosts and IPs are lab artifacts. Shared for portfolio purposes.*

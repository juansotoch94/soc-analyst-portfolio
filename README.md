# SOC Analyst Portfolio — Juan Soto

Blue-team / SOC analyst focused on alert triage, log correlation and evidence-based verdicts. These are incident write-ups from **20 alert-to-closure investigations** I completed in the [LetsDefend](https://letsdefend.io) simulated SOC (95% success rate).

**Verified transcript:** https://app.letsdefend.io/user/Abbyroad
**Credentials (Credly):** https://www.credly.com/users/juan-soto.7417c7d2 — CompTIA Security+ · Blue Team Level 1 (BTL1) · Splunk Core Certified Power User · Fortinet FCF/NSE 1–2

---

## Incident write-ups

Each report follows the same discipline: take the alert, decide true/false positive from **host and network evidence** (not the alert label), map to MITRE ATT&CK, and give a containment recommendation.

| # | Case | Technique | Verdict |
|---|---|---|---|
| 01 | [SharePoint "ToolShell" Auth Bypass → RCE (CVE-2025-53770)](01-sharepoint-toolshell-CVE-2025-53770.md) | Public-facing exploit → RCE → web shell | TP · active compromise |
| 02 | [Lumma Stealer via ClickFix Phishing](02-lumma-stealer-clickfix-phishing.md) | Phishing → user execution → mshta payload | TP · successful |
| 03 | [Command Injection → Active Breach](03-command-injection-active-breach.md) | Command injection → credential access | TP · active breach |

## How I work

- **Evidence over alert metadata.** A firewall "Allowed" is not proof an attack worked; HTTP status codes, response sizes and host process/command history are. I document what I see, not what I assume.
- **Full chain, not just the indicator.** In the Lumma case, the real second-stage C2 domain was only visible on the endpoint — the alert never named it.
- **Escalate on confirmed impact.** Reconnaissance-looking alerts get checked against what the host actually executed before I set severity.

## Toolset

Splunk (SPL) · Windows Event Logs · Wireshark · VirusTotal / AbuseIPDB / URLScan · MITRE ATT&CK · Cyber Kill Chain · EDR containment · phishing & email header analysis (SPF/DKIM/DMARC).

---

*Write-ups are of my own investigations on the LetsDefend training platform; hosts and IPs are lab artifacts. Shared for portfolio purposes.*

# Juan Soto — SOC Analyst Portfolio

Entry-level SOC and security support candidate in South Florida (Miami-Dade / Broward, or remote from Florida). Available for any shift. English and Spanish.

**Certifications:** CompTIA Security+ · Blue Team Level 1 (BTL1) · Splunk Core Certified Power User · Fortinet FCF
[Verified credentials](https://www.credly.com/users/juan-soto.7417c7d2) · [LinkedIn](https://www.linkedin.com/in/juan-soto-693761196/) · [LetsDefend training profile](https://app.letsdefend.io/user/Abbyroad)

## Featured work

| Project | What it shows | Type | Evidence |
|---|---|---|---|
| [Splunk authentication sequence detection](labs/splunk-auth-detection/README.md) | SPL that finds a successful logon after 3+ failures in 300 s for the same user, source and host. Eight test scenarios; a boundary test exposed a defect, which was corrected and re-verified. | Guided lab · synthetic data | Executable SPL, native CSV results, screenshots, reproduction steps |
| [RDP brute-force case (SOC176)](06-rdp-brute-force-account-compromise.md) | Authentication results, endpoint command associations and the limits of attributing activity to one session. | Simulated SOC alert · evidence reviewed | [Evidence register and endpoint screenshots](SOC176-evidence.md) |
| [Ubuntu Server update recovery](labs/ubuntu-update-recovery/README.md) | Diagnosing an interrupted update with `dpkg --audit`, completing configuration and verifying packages, reboot and services. | Guided personal lab | Step-by-step recovery record with stated limits |
| [Splunk data validation before detection](labs/splunk-auth-ingestion/README.md) | Checking event counts, unique IDs and UTC timestamps before trusting a search. | Guided lab · synthetic data | Queries, screenshots, observation files |

## Skills and where to see them

| Skill | Evidence |
|---|---|
| Alert triage and investigation write-ups | [RDP case](06-rdp-brute-force-account-compromise.md), [simulated SOC reports](#simulated-soc-training-letsdefend) |
| Splunk SPL: filtering, grouping, time windows, testing edge cases | [Detection lab](labs/splunk-auth-detection/README.md), [ingestion lab](labs/splunk-auth-ingestion/README.md) |
| Windows authentication events (4624 / 4625) | [Detection lab](labs/splunk-auth-detection/README.md), [RDP case](06-rdp-brute-force-account-compromise.md) |
| Linux command line and package recovery | [Ubuntu recovery](labs/ubuntu-update-recovery/README.md) |
| Separating observations from conclusions | Every featured project ends with what the evidence does **not** show |

## Simulated SOC training (LetsDefend)

Twenty alert investigations completed in LetsDefend's simulated SOC between May and July 2026. The ten reports below are training write-ups. **Only the RDP case has been fully re-reviewed against its evidence**; the others remain learning drafts.

| Case | Investigation focus |
|---|---|
| [SharePoint ToolShell](01-sharepoint-toolshell-CVE-2025-53770.md) | Web requests and subsequent endpoint activity |
| [ClickFix / Lumma Stealer](02-lumma-stealer-clickfix-phishing.md) | Email, proxy and process correlation |
| [Command injection](03-command-injection-active-breach.md) | Requests and host command history |
| [Check Point gateway](04-checkpoint-gateway-file-read-CVE-2024-24919.md) | File-read attempts and response evidence |
| [Internal phishing](05-internal-phishing-threat-hunt.md) | Email context and a separate suspicious download |
| [RDP brute force — evidence reviewed](06-rdp-brute-force-account-compromise.md) | Authentication results, endpoint command associations and attribution limits |
| [PAN-OS command injection](07-panos-command-injection-CVE-2024-3400.md) | Exploit request and device activity |
| [SQL injection](08-sql-injection-analysis.md) | Malicious requests and limits of HTTP evidence |
| [VPN / MFA](09-vpn-unauthorized-country-mfa.md) | Authentication stages and access outcome |
| [Office macro](10-malicious-macro-office-document.md) | Document alert and endpoint execution evidence |

## Next

Independent projects, each published with a case-file write-up and evidence: phishing email header analysis, a basic Active Directory lab, and a blind investigation on a public Splunk dataset. Each will be added only after it is executed and verified.

## Scope and attribution

- **This is training, not employment.** The investigations come from a training platform and the Splunk labs use synthetic data. Scenario identifiers are not presented as live threat intelligence.
- **Guided work is labeled as guided.** Each lab README states what I did and what a mentor or AI assistant supplied or executed.
- **Study drafts are not validated detections.** The [SPL examples](detections/README.md) and [Sigma drafts](detections/sigma-rules.md) have not been tested against ingested data or deployed. A Splunk certification is not a claim of deployment experience.
- **Playbooks are educational outlines.** The [response playbooks](playbooks/README.md) assume containment actions would require an organization's authorization, evidence preservation and impact assessment.

<details>
<summary>Evidence review notes — September 24, 2026</summary>

This review qualifies stronger wording in the earlier reports and queries:

- HTTP status codes and equal response sizes alone do not establish that SQL injection failed; blind or time-based behavior requires additional evidence. A platform training verdict should not be treated as a universal detection rule.
- Command history shows commands were invoked; it does not by itself prove that protected files were read or data was exfiltrated. A payload-download domain is not automatically a command-and-control server.
- The older RDP SPL study draft in `detections/` counts failures and successes without enforcing their order, a bounded time window or the same account. The separate [guided authentication lab](labs/splunk-auth-detection/README.md) now tests those conditions on synthetic data; it does not establish compromise or validate the other study drafts.
- Country and MFA error fields require identity-provider and user context. The current VPN example does not implement impossible-travel detection.
- A suspicious download observed after an email does not establish causation or prove that internal accounts were compromised.

</details>

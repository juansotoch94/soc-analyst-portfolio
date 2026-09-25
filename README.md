# SOC Analyst Portfolio — Juan Soto

I am a career changer pursuing entry-level SOC analyst and SOC support roles. This portfolio documents work from **20 investigations completed in the LetsDefend simulated SOC**, alongside study notes on detection and incident response. These are training investigations, not professional SOC employment.

[Training profile](https://app.letsdefend.io/user/Abbyroad) · [Verified credentials](https://www.credly.com/users/juan-soto.7417c7d2) · [LinkedIn](https://www.linkedin.com/in/juan-soto-693761196/)

**Certifications:** CompTIA Security+ · Blue Team Level 1 (BTL1) · Splunk Core Certified Power User · Fortinet FCF.

## Investigation reports

The reports summarize training notes, scenario evidence, investigation decisions and response recommendations. **Start with the [reviewed RDP case](06-rdp-brute-force-account-compromise.md)**: its September 25 revision includes an [evidence register and two endpoint screenshots](SOC176-evidence.md), with explicit attribution and timestamp limits. Authentication evidence is transcribed from the training interface, not a native raw-log export. Other reports remain learning drafts requiring individual evidence review.

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

## Detection and response study notes

The [SPL detection examples](detections/README.md) and [Sigma drafts](detections/sigma-rules.md) are **unvalidated learning drafts**. They have not been tested against an ingested dataset or deployed in a home lab or production environment. A Splunk certification is not a claim of deployment experience. Field mappings, query correctness and false positives require testing before these examples can be used.

The [response playbooks](playbooks/README.md) are educational outlines. Isolation, account changes and other containment actions require the organization's authorization, evidence-preservation process and assessment of service impact.

## Evidence review notes — September 24, 2026

This review qualifies stronger wording in the earlier reports and queries:

- HTTP status codes and equal response sizes alone do not establish that SQL injection failed; blind or time-based behavior requires additional evidence. A platform training verdict should not be treated as a universal detection rule.
- Command history shows commands were invoked; it does not by itself prove that protected files were read or data was exfiltrated. A payload-download domain is not automatically a command-and-control server.
- The current RDP SPL counts failures and successes without enforcing their order, a bounded time window or the same account. It is a starting point to revise, not a validated compromise detector.
- Country and MFA error fields require identity-provider and user context. The current VPN example does not implement impossible-travel detection.
- A suspicious download observed after an email does not establish causation or prove that internal accounts were compromised.

## Next practical milestone

Validate one small authentication detection with documented input data, field mapping, expected results, a benign comparison and known limitations. Then add reproducible evidence to three selected investigations. No lab completion or successful test is claimed until that work has been performed.

All case material originates from a training platform. Any published identifiers are retained as scenario indicators, not presented as live threat intelligence.

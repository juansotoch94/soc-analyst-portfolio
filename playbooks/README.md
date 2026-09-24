# SOC Response Playbooks

Concise, repeatable response procedures for the incident classes I investigate in my [write-ups](..). Each follows the NIST incident-response lifecycle (Detect → Analyze → Contain → Eradicate → Recover → Lessons Learned) and states the **escalation criteria** up front, because a Tier 1 analyst's job is to act fast on the routine and escalate the rest cleanly.

> These are how I actually work a ticket, distilled. Framework: NIST SP 800-61. Mapped to the [detection rules](../detections) and cases in this portfolio.

---

## 1. Phishing (email → user execution)
**Triggers:** email-security alert, user report, proxy hit on a mail-borne URL. *(Cases [02](../02-lumma-stealer-clickfix-phishing.md), [05](../05-internal-phishing-threat-hunt.md).)*

1. **Analyze the message** — headers (SPF/DKIM/DMARC), sender reputation, URLs and attachments detonated in a sandbox / checked in VirusTotal, URLScan, ANY.RUN. Record every IOC.
2. **Delivered?** Check mail logs — was it delivered, quarantined, or blocked? Delivered changes everything.
3. **Did the user act?** Pivot to proxy/EDR: did the recipient host request the URL or run the attachment? The proxy `Referer` proves the click came from the mail.
4. **Contain:** purge the message from all mailboxes; block sender, URL and domain at mail gateway, proxy and DNS; if execution occurred, isolate the host.
5. **Eradicate / recover:** remove dropped payloads and persistence; reset the user's credentials if a credential-harvesting page was submitted.
6. **Hunt:** search every mailbox for the same sender/subject/URL and every host for the IOCs.
- **Escalate to Tier 2 when:** the payload executed, credentials were entered, or the same campaign hit multiple users.

## 2. Brute force → account compromise
**Triggers:** repeated authentication failures (RDP 4625, VPN, web login) from one source. *(Cases [06](../06-rdp-brute-force-account-compromise.md), [09](../09-vpn-unauthorized-country-mfa.md).)*

1. **Scope it** — one source→one target (focused) or a spray? Enrich the source IP (VirusTotal/AbuseIPDB).
2. **The decisive check — did any attempt succeed?** Failed-then-**success** on the same account (e.g., 4625×N then 4624) turns "someone tried" into "someone is in." For MFA-gated logins, read the second-factor result: "Incorrect OTP" = password compromised, access blocked.
3. **Contain:** on confirmed success, isolate the host and disable/reset the account; block the source IP. On password-compromised-but-MFA-held, reset the credential — no host isolation needed.
4. **Eradicate / recover:** hunt for lateral movement and persistence from the compromised account after the success timestamp; restore the account after cleanup.
5. **Harden:** account-lockout thresholds, MFA/NLA, and remove internet-exposed RDP (put it behind a VPN).
- **Escalate to Tier 2 when:** a login succeeded, or the account is privileged.

## 3. Web / public-facing exploitation (RCE, injection, file read)
**Triggers:** WAF/IDS exploit-pattern alert on an internet-facing app or device. *(Cases [01](../01-sharepoint-toolshell-CVE-2025-53770.md), [03](../03-command-injection-active-breach.md), [04](../04-checkpoint-gateway-file-read-CVE-2024-24919.md), [07](../07-panos-command-injection-CVE-2024-3400.md), [08](../08-sql-injection-analysis.md).)*

1. **Confirm exploitation, not just the attempt** — the device action ("Allowed") is not proof. The **response** is: HTTP status + response size for a file read/SQLi, and the **host process/command history** for RCE. Decode the payload (URL/cookie/body).
2. **Determine impact** — what did the host actually execute or return? Web-server or device process spawning a shell/compiler = confirmed RCE.
3. **Contain:** isolate the affected server/device; block the source IP(s) at the perimeter.
4. **Eradicate:** emergency-patch the CVE; remove web shells and persistence; **rotate any secrets the attacker could read** (patching doesn't undo a credential read).
5. **Recover / hunt:** review for lateral movement, new accounts and config changes after the exploit timestamp.
- **Escalate to Tier 2 when:** exploitation is confirmed on any internet-facing system — treat as active compromise.

## 4. Malware / malicious document on an endpoint
**Triggers:** EDR/AV detection, maldoc alert, suspicious process chain. *(Case [10](../10-malicious-macro-office-document.md).)*

1. **Executed?** Confirm with a process-create event — delivered ≠ run.
2. **What did it do?** Follow the chain (e.g., `WINWORD.exe`→`powershell.exe`→download) and the outbound C2 in the proxy; collect the file hash and URLs.
3. **Detected vs. Quarantined** — "Detected" without "Quarantined" means the analyst drives containment. **Isolate the host** first.
4. **Eradicate:** kill/remove the payload, clear persistence (Run keys, scheduled tasks, services), block the hash/URL/domain fleet-wide.
5. **Recover:** reimage if integrity is uncertain; restore from known-good backup.
6. **Hunt:** the hash and C2 across the fleet; the mail logs for other recipients.
- **Escalate to Tier 2 when:** the payload executed and was not auto-contained, or C2 was reached.

---

*Playbooks reflect my own approach to the investigations in this portfolio, aligned to NIST SP 800-61 and MITRE ATT&CK.*

# Detection Engineering — Splunk (SPL)

Detection logic I built for the attack techniques I investigated in my [incident write-ups](..). Each rule states what it catches, the data source it runs against, the SPL, the MITRE ATT&CK technique, and tuning/false-positive notes — because a detection that pages the SOC every ten minutes is worse than no detection.

> These are illustrative rules written against common Splunk sourcetypes (proxy, firewall, IIS/web, `WinEventLog:Security`, Sysmon). Field names would be mapped to the target environment's data model (e.g., CIM) before deployment. I can walk through the logic and the tuning decisions for any of them.

**Toolset:** Splunk (SPL, `stats`/`tstats`, `eval`, `iplocation`) · Windows Security & Sysmon event logs · MITRE ATT&CK.

---

## 1. SharePoint "ToolShell" exploitation (CVE-2025-53770)
**Catches:** the auth-bypass request pattern *and* the post-exploitation process chain, so you alert on exploitation, not just a scan. See [write-up 01](../01-sharepoint-toolshell-CVE-2025-53770.md).
**Data source:** IIS/web logs + Sysmon (EventCode 1).

Request pattern — POST to `ToolPane.aspx` with the spoofed `SignOut.aspx` referer and an oversized body:
```spl
index=web sourcetype=iis method=POST
| where like(uri_path,"%/ToolPane.aspx%") AND like(uri_query,"%DisplayMode=Edit%")
| where match(http_referer,"(?i)/_layouts/.*SignOut\.aspx")
| where content_length > 5000
| stats count min(_time) as first_seen max(_time) as last_seen values(uri_query) as uris by src_ip, dest_host
```
Post-exploitation — the SharePoint worker process spawning shells/compilers (web-shell drop):
```spl
index=edr sourcetype=Sysmon EventCode=1 ParentImage="*\\w3wp.exe"
    (Image="*\\powershell.exe" OR Image="*\\cmd.exe" OR Image="*\\csc.exe")
| stats values(Image) as children values(CommandLine) as cmds min(_time) as first by dest_host, ParentImage
```
**MITRE:** T1190 · T1059.001 · T1505.003
**Tuning:** legitimate SharePoint rarely spawns `csc.exe`/`powershell.exe` from `w3wp.exe`; allowlist known app-pool automation before enabling as a page-out.

---

## 2. Lumma Stealer via ClickFix (LOLBin execution)
**Catches:** the ClickFix hallmark — `powershell.exe` launching `mshta.exe` (or an HTA/`.mp4`-disguised payload) — and the delivery domain. See [write-up 02](../02-lumma-stealer-clickfix-phishing.md).
**Data source:** Sysmon + proxy.
```spl
index=edr sourcetype=Sysmon EventCode=1
    (ParentImage="*\\powershell.exe" Image="*\\mshta.exe")
    OR (Image="*\\mshta.exe" CommandLine IN ("*http*","*.mp4*","*javascript:*"))
| stats values(CommandLine) as cmds min(_time) as first by dest_host, User, ParentImage, Image
```
Delivery/C2 over the proxy (fake "Windows update" lure domains, second-stage `.shop` C2):
```spl
index=proxy (url="*windows-update.*" OR url="*.shop" OR uri_path="*.mp4")
| stats count values(url) as urls by src_host, user
```
**MITRE:** T1566.002 · T1204 · T1218.005 · T1071
**Tuning:** `mshta.exe` is rare in modern estates — near-zero false positives; scope the `.shop`/`.mp4` proxy rule to unknown/low-reputation domains to keep volume down.

---

## 3. PAN-OS GlobalProtect command injection (CVE-2024-3400)
**Catches:** OS-command / path-traversal payloads smuggled through the GlobalProtect `SESSID` cookie (curl call-back, `${IFS}`, panlog paths). See [write-up 04b](../07-panos-command-injection-CVE-2024-3400.md).
**Data source:** firewall/web logs.
```spl
index=web (uri_path="*/global-protect/*" OR uri_path="*/ssl-vpn/*")
| where match(http_cookie,"(?i)(\$\(|`|\$\{IFS\}|curl|wget|/opt/panlogs|\.\./)")
| stats count min(_time) as first values(http_cookie) as cookies by src_ip, dest_host, uri_path
```
**MITRE:** T1190 · T1059.004
**Tuning:** the `SESSID` cookie is normally an opaque token — any shell metacharacter in it is high-fidelity. Enrich `src_ip` with threat intel to prioritise.

---

## 4. Web command injection — OS commands in the request (whoami / id / cat)
**Catches:** command-injection attempts in the URL or POST body, then confirms execution by pivoting to the host's process history. See [write-up 03](../03-command-injection-active-breach.md).
**Data source:** web logs (+ Sysmon to confirm impact).
```spl
index=web (method=POST OR method=GET)
| where match(uri_query,"(?i)(;|\||`|\$\()\s*(whoami|id|uname|cat\s+/etc/passwd|curl|wget|nc\s)")
      OR match(request_body,"(?i)(whoami|/etc/passwd|/bin/bash|\$\(.*\))")
| stats count values(uri_query) as payloads by src_ip, dest_host
```
Confirm it actually ran (turn "someone tried" into "someone is in"):
```spl
index=edr sourcetype=Sysmon EventCode=1 host=<dest_host>
    Image IN ("*\\whoami.exe","*/bin/sh","*/bin/bash","*/usr/bin/id")
| stats values(CommandLine) by host, ParentImage
```
**MITRE:** T1190 · T1059
**Tuning:** the request-side rule is noisy on its own (scanners probe constantly) — alert at **medium**, and escalate to **high** only when the host process-execution search corroborates it.

---

## 5. RDP brute force that succeeded
**Catches:** the pattern that actually matters — many failed logons from one source to one host on RDP, **followed by a success** on the same account. Volume of failures alone is only "someone tried." See [write-up 06](../06-rdp-brute-force-account-compromise.md).
**Data source:** `WinEventLog:Security` (Logon Type 10 = RemoteInteractive/RDP).
```spl
index=win sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624) Logon_Type=10
| stats count(eval(EventCode=4625)) as failed
        count(eval(EventCode=4624)) as success
        min(_time) as first max(_time) as last
        values(Account_Name) as accounts by src_ip, dest_host
| where failed >= 10 AND success >= 1
| eval window_min=round((last-first)/60,1)
```
**MITRE:** T1110 · T1078.002 · T1021.001
**Tuning:** raise the `failed` threshold for hosts behind a jump box that legitimately sees many logons; the `success >= 1` condition is what keeps this from firing on failed-only spray.

---

## 6. SQL injection — with a success-vs-blocked verdict
**Catches:** SQLi payloads, and — critically — separates a *successful* extraction from a *blocked* attempt using response status and response-size variety, instead of trusting the firewall's "Allowed". See [write-up 08](../08-sql-injection-analysis.md).
**Data source:** web logs.
```spl
index=web
| where match(uri_query,"(?i)(union\s+select|or\s+1\s*=\s*1|information_schema|xp_cmdshell|sleep\(|--|/\*)")
| stats count dc(response_bytes) as size_variety values(status) as statuses
        min(_time) as first by src_ip, dest_host
| eval verdict=case(size_variety>2 AND match(mvjoin(statuses,","),"200"),"REVIEW – possible data return",
                    match(mvjoin(statuses,","),"^(500|403)"),"likely blocked/error",
                    true(),"needs review")
```
**MITRE:** T1190 · T1505
**Tuning:** identical response sizes with a `500`/`403` status = the injection isn't returning data (blocked); varied sizes with `200` = pull the responses and confirm. This is the single most common false-escalation I see junior analysts make, so the rule encodes the check.

---

## 7. VPN login from an unauthorized country (with MFA context)
**Catches:** VPN authentication from an anomalous geography, correlated with OTP/MFA outcome — so you can tell a *compromised password stopped by MFA* apart from a *full account takeover*. See [write-up 09](../09-vpn-unauthorized-country-mfa.md).
**Data source:** VPN / auth logs.
```spl
index=vpn (action=success OR action="Incorrect OTP*" OR action=failure)
| iplocation src_ip
| search NOT Country="United States"
| stats values(action) as outcomes count by user, src_ip, Country, City
| eval risk=case(match(mvjoin(outcomes,","),"success"),"ACCOUNT TAKEOVER – isolate",
                 match(mvjoin(outcomes,","),"(?i)incorrect otp"),"password compromised, MFA held – reset creds",
                 true(),"failed attempt")
```
**MITRE:** T1133 · T1078 · T1621
**Tuning:** pair with an "impossible travel" lookup (same user, two countries inside a physically impossible window) to cut single-trip-abroad false positives.

---

*Rules are written from my own SOC investigations. Field names are illustrative and would be normalized to the destination environment's schema (Splunk CIM) at deployment.*

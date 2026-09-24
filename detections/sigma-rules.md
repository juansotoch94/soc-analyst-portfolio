# Detection-as-Code — Sigma Rules

The same detections from my [Splunk SPL set](README.md), written as **[Sigma](https://github.com/SigmaHQ/sigma) rules** — the vendor-agnostic detection standard. Sigma rules convert to Splunk, Sentinel (KQL), Elastic, and most SIEMs, so the logic travels with me instead of being locked to one platform. Each maps to a case in the [write-ups](..) and to MITRE ATT&CK.

> Written from my own SOC investigations. Field names follow the Sigma taxonomy and would be validated against the target's pipeline before deployment.

---

## 1. SharePoint "ToolShell" auth bypass (CVE-2025-53770)
```yaml
title: SharePoint ToolShell Auth Bypass Attempt (CVE-2025-53770)
id: 6f2a1c3e-9b4d-4e21-8a7c-1f0e2d3c4b5a
status: experimental
description: POST to ToolPane.aspx in edit mode with a spoofed SignOut.aspx referer, indicative of CVE-2025-53770 exploitation.
references:
  - https://github.com/juansotoch94/soc-analyst-portfolio/blob/main/01-sharepoint-toolshell-CVE-2025-53770.md
author: Juan Soto
date: 2026/09/23
logsource:
  category: webserver
detection:
  selection:
    cs-method: 'POST'
    cs-uri-stem|contains: '/ToolPane.aspx'
    cs-uri-query|contains: 'DisplayMode=Edit'
    cs-referer|contains: 'SignOut.aspx'
  condition: selection
falsepositives:
  - Legitimate SharePoint automation is rare with this exact request shape
level: high
tags:
  - attack.initial_access
  - attack.t1190
  - attack.t1505.003
```

## 2. Web server process spawning a shell/compiler (web-shell / RCE)
```yaml
title: Web Server Worker Process Spawning Shell or Compiler
id: b1d9f4a2-3c8e-4a56-9d21-7e6f5a4b3c2d
status: experimental
description: IIS worker (w3wp.exe) spawning powershell/cmd/csc — the post-exploitation signature behind ToolShell and other web RCE. Catches exploitation, not just the request.
references:
  - https://github.com/juansotoch94/soc-analyst-portfolio/blob/main/03-command-injection-active-breach.md
author: Juan Soto
date: 2026/09/23
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\w3wp.exe'
    Image|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
      - '\csc.exe'
  condition: selection
falsepositives:
  - Some app pools legitimately compile at runtime; allowlist per host
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1505.003
```

## 3. ClickFix / Lumma Stealer — PowerShell launching mshta
```yaml
title: PowerShell Spawning MSHTA (ClickFix / LOLBin Execution)
id: 3e7c8a9b-1d2f-4c65-b8a3-9f0e1d2c3b4a
status: experimental
description: powershell.exe launching mshta.exe (often against an HTA or a .mp4-disguised payload) — the ClickFix execution hallmark seen delivering Lumma Stealer.
references:
  - https://github.com/juansotoch94/soc-analyst-portfolio/blob/main/02-lumma-stealer-clickfix-phishing.md
author: Juan Soto
date: 2026/09/23
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\powershell.exe'
    Image|endswith: '\mshta.exe'
  condition: selection
falsepositives:
  - mshta.exe is rare in modern estates; near-zero expected
level: high
tags:
  - attack.execution
  - attack.t1218.005
  - attack.t1059.001
```

## 4. Office application spawning PowerShell (malicious macro)
```yaml
title: Office Application Spawning PowerShell (Maldoc)
id: 9a4b2c1d-6e5f-4a38-b7c9-2d1e0f3a4b5c
status: experimental
description: WINWORD/EXCEL/POWERPNT spawning powershell.exe — the macro-dropper-to-downloader pattern (e.g., edit1-invoice.docm pulling a second stage).
references:
  - https://github.com/juansotoch94/soc-analyst-portfolio/blob/main/10-malicious-macro-office-document.md
author: Juan Soto
date: 2026/09/23
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
    Image|endswith: '\powershell.exe'
  condition: selection
falsepositives:
  - Rare legitimate Office add-ins; investigate the command line
level: high
tags:
  - attack.execution
  - attack.t1566.001
  - attack.t1059.001
  - attack.t1204.002
```

## 5. Web command injection — OS commands in the request
```yaml
title: OS Command Keywords in Web Request (Command Injection)
id: c5d6e7f8-2a3b-4c19-9e8d-7f6a5b4c3d2e
status: experimental
description: Shell metacharacters followed by OS commands (whoami/id/cat /etc/passwd/curl) in the URL or body — command-injection probing against a public-facing app. Corroborate with host process execution before escalating.
references:
  - https://github.com/juansotoch94/soc-analyst-portfolio/blob/main/03-command-injection-active-breach.md
author: Juan Soto
date: 2026/09/23
logsource:
  category: webserver
detection:
  selection:
    cs-uri-query|re: '(?i)(;|\||`|\$\()\s*(whoami|id|uname|cat\s+/etc/passwd|curl|wget|nc\s)'
  condition: selection
falsepositives:
  - Scanners probe constantly; pair with host process-execution evidence
level: medium
tags:
  - attack.initial_access
  - attack.t1190
  - attack.t1059
```

---

*These Sigma rules mirror the SPL detections in this folder and are shared as detection-as-code samples. UUIDs are placeholders for illustration.*

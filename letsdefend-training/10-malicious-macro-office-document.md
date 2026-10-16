# Incident Report — Malicious Office Macro → PowerShell Payload Download

**Analyst:** Juan Soto · **Environment:** LetsDefend simulated SOC · **Alert:** SOC205 (Event ID 231) · **Severity:** Medium → escalated · **Verdict:** True Positive — macro executed, payload not quarantined

> Educational SOC investigation on the LetsDefend training platform. All hosts and IPs are lab artifacts.

---

## Executive summary

A macro-enabled Word document (`edit1-invoice.docm`) landed in a user's Downloads and was **opened on host `Jayne` (172.16.17.198)**. On open, the macro launched **PowerShell to download a second-stage executable** (`messbox.exe`) from a known-malicious host. The endpoint agent **detected but did not quarantine** the activity, so the threat was live on the box. Closed as a True Positive and escalated for host containment.

## Alert details

| Field | Value |
|---|---|
| Rule | SOC205 — Malicious Macro Has Been Executed |
| Event time | 2024-02-28 08:42 |
| Host | `Jayne` (172.16.17.198) |
| File | `edit1-invoice.docm` — `C:\Users\LetsDefend\Downloads\` |
| SHA-256 | `1a819d18c9a9de4f81829c4cd55a17f767443c22f9b30ca953866827e5d96fb0` |
| AV/EDR action | **Detected (not quarantined)** |

## Investigation

1. **Was it actually executed?** Log Management showed a **process-create** for `edit1-invoice.docm` at 08:42 — the document wasn't just delivered, it ran.
2. **What did the macro do?** At the same timestamp the proxy logged a **PowerShell GET request** to `http://www.greyhathacker.net/tools/messbox.exe` — the macro used `powershell.exe` (a living-off-the-land binary) to pull a second stage. Classic maldoc behaviour: the document is the dropper, PowerShell is the downloader.
3. **Reputation.** The download URL is flagged **malicious on VirusTotal**; the file hash is a known bad indicator.
4. **Did the payload land / did the agent stop it?** The proxy device action was **"permit"** — the request to the malware host was allowed — and the endpoint agent shows **"Detected" but not "Quarantined."** Detection without quarantine means the analyst, not the tool, has to drive containment.

## Verdict & impact

**True Positive — macro executed, second-stage retrieval allowed, not quarantined.** The user opened a weaponized document that reached out for a payload, and nothing automatically contained it. `Jayne` must be treated as potentially compromised until proven clean.

## MITRE ATT&CK

- **T1566.001** — Phishing: Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1105** — Ingress Tool Transfer · **T1071** — Application Layer Protocol

## Response & recommendations

1. **Isolate `Jayne`** — detection without quarantine means the threat may be resident; contain first, analyze second.
2. **Confirm and remove** the payload: check whether `messbox.exe` downloaded/executed, kill it, and pull persistence (Run keys, scheduled tasks, services).
3. **Block** `greyhathacker.net` / the payload URL at proxy and DNS; add the file hash to EDR blocklist.
4. **Hunt** the hash and URL across the fleet, and check mail logs for other recipients of `edit1-invoice.docm`.
5. **Reduce exposure:** block macros from the internet by policy (Mark-of-the-Web enforcement) and alert on `WINWORD.exe`/`EXCEL.exe` spawning `powershell.exe`.

## Lesson learned

An endpoint alert that says **"Detected"** is not the same as **"Quarantined."** The tool saw the macro but left the payload path open, so the containment decision fell to the analyst. Confirming execution (process-create) and the outbound download (proxy) turned a medium "macro" alert into a host-compromise response — and the Office-app-spawns-PowerShell pattern is the detection worth building so the next one pages sooner.

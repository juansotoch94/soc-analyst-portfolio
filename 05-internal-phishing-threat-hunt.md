# Incident Report — Internal-to-Internal Phishing → Threat-Hunt Finding

**Analyst:** Juan Soto · **Environment:** LetsDefend simulated SOC · **Alert:** SOC120 (Event ID 52) · **Severity:** Medium · **Verdict:** email alert = benign on its own evidence; **parallel host compromise found during hunting**

> Educational SOC investigation on the LetsDefend training platform. All users, hosts and IPs are lab artifacts.

---

## Executive summary

An internal-to-internal email (`john@letsdefend.io` → `susie@letsdefend.io`) triggered a phishing alert. The email itself carried no attachment or URL, so on its own evidence it was not malicious. But rather than close it there, I checked what the recipient host actually did afterward — and found that **`SusieHost` reached out to a malicious executable ~14 hours later**. Two internal mailboxes that had been dormant for months were being used to stage an attack. The download was blocked by the proxy, but the pattern pointed to **compromised internal accounts**, which is a separate, higher-priority finding than the email that surfaced it.

## Alert details

| Field | Value |
|---|---|
| Rule | SOC120 — Phishing Mail Detected — Internal to Internal |
| Event time | 2021-02-07 04:24:09 |
| From → To | `john@letsdefend.io` → `susie@letsdefend.io` |
| Subject | "Meeting" |
| Attachments / URLs | None in the message body |

## Investigation

1. **Parse the email.** No links, no attachments — nothing directly weaponised in the message itself. A naive close would be "false positive" here.
2. **Context on the accounts.** Both endpoints were suspicious by their inactivity: `JohnComputer` last logged in Oct 2020, `SusieHost` last logged in Aug 2020 — yet this internal "Meeting" email appeared in Feb 2021. Dormant accounts suddenly emailing each other is a red flag for account compromise.
3. **What did the recipient host do next?** Pivoting to `SusieHost` activity, it generated **outbound web traffic on 2021-02-07 at 18:32 — about 14 hours after the email** — a `GET` request to:
   `hxxp://gavrilobtcapikey2884238984928[.]netsons[.]org/pianificazione.exe`
4. **Reputation & process context.** The URL was **malicious in VirusTotal (6/91)**. The request came from `chrome.exe` spawned by `explorer.exe`. The **download was blocked by the proxy** — so no payload landed, but the intent and the staging are clear.

## Verdict & impact

- **The email alert itself:** benign on its own evidence (no payload) — but it was the thread that led to the real finding.
- **The real finding:** two dormant internal accounts being used to stage a malware delivery attempt, with `SusieHost` actively trying to pull `pianificazione.exe`. Blocked this time, but the accounts should be treated as **compromised**. This is opened as its own incident, not folded into the email's verdict.

## MITRE ATT&CK

- **T1566** — Phishing (internal, likely from compromised accounts)
- **T1071** — Application Layer Protocol (web) for payload retrieval
- Supporting: T1078 — Valid Accounts (dormant internal accounts reused)

## Response & recommendations

1. **Open a separate incident** for the `SusieHost` / `JohnComputer` account compromise — don't let it die inside a "phishing FP" close.
2. **Reset credentials** and force re-auth for both accounts; review their recent authentication and mail-send activity.
3. **Block** the `netsons.org` payload URL/domain at proxy and DNS; add to threat intel.
4. **Hunt** for the same URL/host pattern and for other dormant accounts that suddenly became active.

## Lesson learned

Each alert should close on **its own evidence** — the email genuinely had no payload — but "no payload in the mail" is not the same as "nothing is wrong." Looking past the alert to what the host actually did turned a would-be false positive into the discovery of a staged internal compromise. Unrelated findings get their own ticket; the alert doesn't get force-fit to match them, and the hunt doesn't get dropped just because the original artifact was clean.

# Incident Report — RDP Brute Force and Successful Authentication

**Analyst:** Juan Soto · **Environment:** LetsDefend simulated SOC · **Alert:** SOC176 (Event ID 234) · **Platform severity:** Medium · **Platform verdict:** True Positive — successful brute force

> Educational SOC investigation on the LetsDefend training platform. All hosts and IPs are lab artifacts.

**Review status:** Bounded mentor-assisted evidence review completed on September 25, 2026. Includes an [evidence register and two endpoint screenshots](SOC176-evidence.md). Authentication results and the platform's command-to-process associations were checked; attribution of those commands to the RDP session and the history of response actions remain unresolved. This is an assessed scope, not a claim of full forensic closure.

---

## Executive summary

The training scenario concerns repeated RDP authentication attempts from `218.92.0.56` to `Matthew` (`172.16.17.148:3389`). A source-address search returned 15 firewall records and 15 OS records. The OS records show 14 failed logons across four account names and one successful remote-interactive logon for `Matthew`. Two failures for `Matthew` immediately precede that success. The platform classifies the case as successful brute force; the observed authentication sequence supports that assessment. Activity after the logon and the extent of impact have not yet been established in this review.

## Alert details

| Field | Value |
|---|---|
| Rule | SOC176 — RDP Brute Force Detected |
| Alert time in Monitoring | 2024-03-07T11:44:00+03:00 |
| Source IP | 218.92.0.56; the scenario feedback reports 11 VirusTotal detections, not a current reputation lookup |
| Destination | 172.16.17.148 (`Matthew`), port 3389 (RDP) |
| Protocol | RDP |

## Investigation

1. **Query.** In [Log Management](https://app.letsdefend.io/logmanagement/logs), apply Source Address contains `218.92.0.56` with All Time selected. Both result pages were reviewed during the mentor-assisted check.
2. **Separate network and authentication evidence.** The 30 results comprise 15 Firewall and 15 OS records. Firewall traffic to port 3389 does not establish whether authentication succeeded. The OS records contain 14 event 4625 failures and one event 4624 success.
3. **Account correlation.** Failed account names are `sysadmin` (6), `admin` (3), `guest` (3), and `Matthew` (2). The successful account is `Matthew`. All reviewed results point to `172.16.17.148:3389`; this is the observed query scope, not proof that the source never contacted another asset.
4. **Authentication evidence.** The following adjacent OS events establish the account, source, order and successful session type:

| Displayed time, March 7, 2024 | EventID | Username | Source IP | Relevant field |
|---|---|---|---|---|
| 03:44:57 | 4625 | Matthew | 218.92.0.56 | Error Code 0xC000006A |
| 03:44:58 | 4625 | Matthew | 218.92.0.56 | Error Code 0xC000006A |
| 03:44:59 | 4624 | Matthew | 218.92.0.56 | Logon Type 10 (RemoteInteractive) |

Log Management did not display a timezone alongside these timestamps. They are preserved as shown and are not labelled UTC. The displayed fields are platform log records, not a native Windows XML export. Microsoft documents [4624 and logon type 10](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) and [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625).

## Verdict & impact

The initial endpoint review found `net.exe` (PID 3496), parent `cmd.exe`, with command line `net localgroup administrators`. Its displayed Process User is `EC2AMAZ-ILGVOIN\LetsDefend`, not the `Matthew` username in the successful authentication. The command requests local Administrators group membership information; it does not add a member. No command output was reviewed. Session attribution and the differing timestamp displays require correlation before treating this as activity by the RDP actor. [Command reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc725622%28v%3Dws.11%29).

Juan also identified `whoami`, verified in Target Process Command Line of a `cmd.exe` row (PID 5360) at 11:45:51 on March 7, 2024. A second `cmd.exe` row at 11:46:34 shows the same PID, Process User `EC2AMAZ-ILGVOIN\LetsDefend`, parent `explorer.exe`, and Target Process Command Line `net localgroup administrators`. The platform thus associates the two queries with the same interpreter PID, user and host, 43 seconds apart by row timestamps. [Evidence E2 and E3, with screenshots](SOC176-evidence.md).

PID 5360 belongs to the displayed cmd.exe, not a separately verified whoami.exe process. Without arguments, `whoami` requests the current domain and user name; its presence alone does not establish malicious intent. No output was reviewed. Checking whether the current account belonged to Administrators is plausible, not a confirmed purpose. The process association is documented, but attribution to the RDP session remains unresolved. [Microsoft: whoami](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/whoami).

**Platform verdict: True Positive — successful brute force.** Verified evidence confirms a remote-interactive authentication for `Matthew` after repeated failures from the same source, including two failures for that account. The attack interpretation combines the pattern with scenario context; event 4624 alone does not identify the person using the credentials. Endpoint command records have been observed, but the reviewed evidence does not yet link them to this authenticated session or establish data access, persistence, lateral movement, or compromise of other reachable systems.

## MITRE ATT&CK

- **T1110 — Brute Force:** the scenario's primary attack classification, supported by repeated failed authentication attempts.
- **T1078 — Valid Accounts:** consistent with the scenario's interpretation of the successful authentication. A domain-account subtype is not established by the displayed fields.

RDP was used for the successful remote session. Lateral movement and account-discovery activity after access have not been verified in this review.

## Response & recommendations

These are proposed actions, not a record of actions performed:

1. Escalate with the failed and successful authentication records, the affected account and host, and the unresolved impact.
2. Evaluate containment under the organization's procedure, including host isolation or account/session restrictions where appropriate to the risk, authority and operational impact. The scenario feedback recommends isolation.
3. Review activity associated with the successful session and check for access to other systems. Preserve relevant evidence and verify timestamps before correlating different sources.
4. Review remote-access exposure, authentication controls and the account's credentials as part of remediation planning. Record what was actually changed and by whom rather than treating recommendations as completed work.

Endpoint Security currently displays **Host Contained**. This observation does not identify when containment occurred or who performed it; no containment setting was changed during this review.

## Lesson learned

Identify the evidence behind each claim: firewall records describe network traffic, authentication records establish logon results, and session activity helps determine impact. Here, the relevant success is an OS event 4624 with logon type 10. Severity and containment still depend on context and impact, not one event ID or a training-platform score.

# Incident Report — Command Injection → Active Breach (`whoami` in request body)

**Analyst:** Juan Soto · **Environment:** LetsDefend simulated SOC · **Alert:** SOC168 (Event ID 118) · **Severity:** High → escalated Critical · **Verdict:** True Positive — active breach

> Educational SOC investigation on the LetsDefend training platform. All hosts and IPs are lab artifacts.

---

## Executive summary

A web server (`WebServer1004`, 172.16.17.16) received a `POST` request with the string `whoami` in its body. On its own that reads as low-severity reconnaissance — but pivoting to the host's command history showed the attacker had already run a **full credential-access chain** (`whoami → uname → cat /etc/passwd → cat /etc/shadow`), confirming successful command injection and an **active breach in progress**. Escalated immediately under active-compromise protocol.

## Alert details

| Field | Value |
|---|---|
| Rule | SOC168 — Whoami Command Detected in Request Body |
| Event time | 2022-02-28 04:12:45 |
| Source IP | 61.177.172.87 (China, AS4837 — known-bad on AbuseIPDB) |
| Destination | 172.16.17.16 (`WebServer1004`) |
| Method / URL | `POST https://172.16.17.16/video/` |
| Trigger | Request body contains `whoami` |

## Investigation

1. **Confirm the trigger is real.** Filtered Log Management by the source IP and located the request. The body genuinely contained a `whoami` command injected into a POST parameter — not a false match on the string.
2. **Was it a one-off?** Reviewing the attacker's other requests showed **multiple commands**, not a single probe.
3. **Did the commands actually run?** Pivoted to `WebServer1004` → **Command History** (Endpoint Security). The executed chain:

   ```
   whoami
   uname            (host / kernel fingerprinting)
   cat /etc/passwd  (user enumeration)
   cat /etc/shadow  (password-hash access)
   ```

   The presence of these in the host's command history proves the injected commands **executed successfully** — the attacker reached `/etc/shadow`, i.e. credential material, not just attempted access.

## Verdict & impact

**True Positive — active breach.** External attacker achieved command execution on an internet-facing web server and progressed to credential access (`/etc/shadow`). This is confirmed impact, not a scan.

## MITRE ATT&CK

- **T1190** — Exploit Public-Facing Application (command injection)
- **T1059** — Command and Scripting Interpreter
- **T1003.008** — OS Credential Dumping: /etc/passwd and /etc/shadow
- Supporting: T1033 (`whoami`), T1082 (`uname` — system info)

## Response & recommendations

1. **Escalate to Tier 2 / IR immediately** and **isolate `WebServer1004`** — active compromise with credential access.
2. **Force-rotate credentials** for any accounts on the host; assume `/etc/shadow` hashes are exfiltrated and crackable offline.
3. **Block** source IP 61.177.172.87 at the perimeter.
4. **Root-cause the injection point** in the `/video/` endpoint (input validation / parameterization) and patch.
5. **Hunt** for persistence and lateral movement from the host during the attack window.

## Lesson learned

A bare `whoami` in a request body is easy to dismiss as noise. The escalation only happened because I checked what the host *actually executed* rather than what the alert *matched on*. The standing rule I took from this: when command execution is even possible, confirm it against endpoint command history before deciding severity — and escalate on confirmed active compromise regardless of the alert's original label.

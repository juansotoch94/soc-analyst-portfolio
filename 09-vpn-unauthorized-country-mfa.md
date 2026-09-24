# Incident Report — VPN Login from Unauthorized Country (MFA Held the Line)

**Analyst:** Juan Soto · **Environment:** LetsDefend simulated SOC · **Alert:** SOC257 (Event ID 225) · **Severity:** Low → re-weighted · **Verdict:** True Positive — compromised credentials, access blocked by MFA

> Educational SOC investigation on the LetsDefend training platform. All users, hosts and IPs are lab artifacts.

---

## Executive summary

A VPN authentication for `monica@letsdefend.io` came from **113.161.158.12 in Vietnam** at ~02:01 local, a country the organization doesn't operate from. The important detail is what the logs showed next: the attacker **entered Monica's password correctly**, which triggered an OTP — but, unable to receive that OTP, they **failed the one-time-code twice and were denied**. So this is not a false positive and not a full takeover; it's a **confirmed credential compromise that multi-factor authentication stopped**. The distinction drives the response: reset credentials, but no host isolation is warranted because no access was gained.

## Alert details

| Field | Value |
|---|---|
| Rule | SOC257 — VPN Connection Detected from Unauthorized Country |
| Event time | 2024-02-13 02:04 |
| User | `monica@letsdefend.io` |
| Source IP | 113.161.158.12 (Vietnam; malicious in AbuseIPDB / VirusTotal — Brute Force, Web Attack) |
| Portal | `https://vpn-letsdefend.io` |

## Investigation

1. **TP or FP?** The firewall log at 02:01 shows the action **"Incorrect OTP Code."** That means authentication got *past the password* and reached the OTP stage — so the alert is a **True Positive**: a real, unauthorized authentication attempt with valid credentials. (Had the alert only fired on a completed VPN *login*, it would have been a false positive, since login never completed.)
2. **Reputation.** The source IP is external, geolocated to Vietnam, and reported malicious across AbuseIPDB, VirusTotal and LetsDefend Threat Intel.
3. **How far did it get?** The attacker knew Monica's password (entered correctly, OTP was issued) but **could not supply the correct OTP** — tried twice, one minute apart, failed both. MFA blocked the session.
4. **Impact check.** No critical system was reached; no session established. Monica's **password is compromised**, but her **account was not taken over**.

## Verdict & impact

**True Positive — compromised credentials, access prevented by MFA.** Monica is a compromised-credential case, not an owned account. Sensitive data was not at risk on this attempt because the second factor held. The value of the investigation is not over-reacting (no takeover) while not under-reacting (the password is genuinely burned).

## MITRE ATT&CK

- **T1133** — External Remote Services (VPN)
- **T1078** — Valid Accounts (attacker holds valid credentials)
- **T1621** — Multi-Factor Authentication Request Generation

## Response & recommendations

1. **Reset Monica's password** and any place she reused it — the password is known to an attacker.
2. **No host isolation required** — no session was established and no endpoint was touched; isolating would be effort spent where there's no access. (Getting this call right is the point of the investigation.)
3. **Block** 113.161.158.12 at the VPN/perimeter and add to intel.
4. **Review** how the password leaked (credential-stuffing list, phishing, reuse) and confirm MFA is enforced for every remote-access account.
5. **Add detection** for impossible travel and repeated OTP failures per user.

## Lesson learned

The severity of an identity alert hinges on one question the logs can answer: did the second factor hold? "Incorrect OTP" is the difference between *someone knows the password* and *someone is inside*. Reading that field correctly avoided both mistakes — dismissing a real credential compromise as noise, and escalating to a full account-takeover response that the evidence didn't support.

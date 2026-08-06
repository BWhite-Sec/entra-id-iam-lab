# Security Incident Report — Microsoft Entra ID IAM Lab

*Risky Sign-In Detection & Over-Permissioned Application Review*

| Field | Value |
|---|---|
| **Report ID** | ENTRA-LAB-2026-001 |
| **Analyst** | Brandon White |
| **Environment** | Microsoft Entra ID tenant (`brandondevwhiteoutlook.onmicrosoft.com`), Entra ID P2 (30-day trial) |
| **Date of Activity** | August 6, 2026 |
| **Severity** | Low–Medium (simulated / lab environment) |
| **Status** | Detected — Investigated — Closed (planned exercise) |
| **MITRE ATT&CK** | T1078.004, T1098.003, T1550.001 |
| **Related project** | [ad-iam-kerberoasting-lab](https://github.com/BWhite-Sec/ad-iam-kerberoasting-lab) — on-prem counterpart to this lab |

---

## 1. Executive Summary

This report documents two controlled scenarios run against a self-provisioned
Microsoft Entra ID P2 tenant, built to demonstrate cloud identity detection
and access-governance skills as the companion piece to an existing on-prem
Active Directory Kerberoasting lab.

**Scenario A** simulated an implausible-travel sign-in pattern using a
legitimate test account (`jdoe`) authenticating from two geographically
distant locations within a short time window. Microsoft Entra ID Protection
flagged the activity as an **Anonymous IP address** risk detection (Low
risk); a manually-built Splunk detection independently confirmed the same
pattern by calculating time-and-location deltas directly from raw sign-in
log data.

**Scenario B** reviewed a deliberately over-permissioned application
registration (`svc-automation`) that was granted a broad, tenant-wide
Microsoft Graph permission (`User.Read.All`, Application-level) with admin
consent and no attached review cadence — a stand-in for the "illicit
consent grant" attack pattern seen in real-world cloud identity
compromises.

Both scenarios were investigated, triaged, and — in Scenario A's case —
formally dismissed with documented reasoning, consistent with real SOC
analyst workflow rather than reflexive alert response.

---

## 2. Environment & Architecture

| Component | Details |
|---|---|
| **Identity tenant** | Microsoft Entra ID, `brandondevwhiteoutlook.onmicrosoft.com` |
| **License** | Microsoft Entra ID P2 (30-day Managed Trial) |
| **Users** | `jdoe` (Finance), `asmith` (IT-Admins), both P2-licensed |
| **Groups** | IT-Admins, Finance, All-Staff (assigned-membership security groups) |
| **Non-human identity** | `svc-automation` app registration — single-tenant, `User.Read.All` (Application, admin-consented) |
| **Log-shipping identity** | `entra-log-shipper` app registration — single-tenant, `AuditLog.Read.All` + `Directory.Read.All` (Application, admin-consented) |
| **Log pipeline** | Python script (MSAL client-credentials flow) → Microsoft Graph `auditLogs/signIns` → Splunk HTTP Event Collector → `index=entra`, `sourcetype=entra_signin_log` |
| **SIEM** | Splunk Enterprise (Ubuntu Server, VirtualBox) — same indexer reused from `splunk-siem-lab` and `ad-iam-kerberoasting-lab` |

Conditional Access was configured with two policies, both run in
**report-only mode** for the duration of this exercise so their evaluation
logic could be validated before enforcement:

| Policy | Scope | Grant | Mode |
|---|---|---|---|
| Baseline - Require MFA for All Users | All users (break-glass admin excluded) | Require MFA | Report-only |
| Risk-Based - Require MFA on Medium+ Sign-In Risk | All users (break-glass admin excluded) | Require MFA on Medium/High sign-in risk | Report-only |

Privileged Identity Management (PIM) was configured with `asmith` as an
**eligible** (not standing/active) assignment for the Security Reader role,
with a bounded one-year eligibility window rather than permanent
eligibility, and was activated once with a documented justification to
validate the just-in-time access flow end to end.

---

# Part A — Detection (SOC Angle)

## 3. Scenario A: Implausible-Travel Sign-In

### 3.1 Timeline

| Time (Local) | Location | IP Address | Status |
|---|---|---|---|
| 9:49–9:51 AM | Katy, Texas, US | 170.203.113.88 | Success (with one interrupted attempt) |
| 11:07–11:09 AM | Querétaro, Querétaro, Mexico | 149.88.22.26 | Success (via Surfshark VPN) |
| 11:12 AM | Houston, Texas, US | 149.40.56.18 | Success |

The Mexico sign-in occurred roughly **76 minutes** after the Katy, TX
sign-in, and the return-to-Houston sign-in occurred roughly **3 minutes**
after that — both intervals implausible for legitimate travel between the
two locations, consistent with the intended VPN-simulated impossible-travel
pattern.

### 3.2 Native Detection: Identity Protection

Microsoft Entra ID Protection's **Risk detections** report flagged three
events on the `jdoe` account, all tied to IP `149.40.56.18`:

| Detection Time | Detection Type | Risk State | Risk Level |
|---|---|---|---|
| 11:12:49 AM | Anonymous IP address | Remediated | Low |
| 11:12:45 AM | Anonymous IP address | Remediated | Low |
| 11:12:28 AM | Anonymous IP address | At risk → Dismissed | Low |

Notably, Identity Protection's **Atypical travel** detection — the
heuristic most directly associated with impossible-travel scenarios — did
**not** fire. Instead, **Anonymous IP address** was the detection type that
triggered.

**Why Atypical travel didn't fire (analysis):** Atypical travel is a
machine-learning model that relies on a user's historical sign-in pattern
to establish a baseline of "normal" behavior before it can flag a
deviation from it. `jdoe` was a brand-new account with fewer than ten total
sign-ins, all generated within the same test session — there was no
established baseline for the model to compare against. Anonymous IP
address, by contrast, is a reputation-based detection tied to Microsoft's
threat intelligence feed identifying the IP itself as a known VPN/proxy
exit node, and does not require sign-in history to fire. This is a
meaningful operational finding in its own right: **detection maturity for
new or low-history accounts is inherently weaker**, and analysts should not
assume the absence of an Atypical travel flag means the absence of
suspicious travel behavior.

### 3.3 Manually Built Detection (Splunk)

Rather than relying solely on Identity Protection's built-in flag, a
correlation query was built directly against raw sign-in log data pulled
via the Graph API pipeline (Section 5), to independently validate the
travel-time logic:

```spl
index=entra sourcetype=entra_signin_log
| eval city=coalesce('location.city',"unknown")
| sort 0 userPrincipalName, createdDateTime
| streamstats current=f last(city) as prev_city, last(createdDateTime) as prev_time by userPrincipalName
| where isnotnull(prev_city) AND city!=prev_city
| eval minutes_between=round((strptime(createdDateTime,"%Y-%m-%dT%H:%M:%S%Z") - strptime(prev_time,"%Y-%m-%dT%H:%M:%S%Z"))/60, 1)
| where minutes_between < 120
| table userPrincipalName, prev_city, city, minutes_between, createdDateTime
```

**Results:**

| User | Previous City | New City | Minutes Between |
|---|---|---|---|
| jdoe@... | Katy | Querétaro | 76.1 |
| jdoe@... | Querétaro | Houston | 2.8 |

This query independently confirmed the same travel pattern Identity
Protection's Anonymous IP detection surfaced, without depending on
Microsoft's risk-scoring model at all. Building this detection manually —
rather than only screenshotting the native Identity Protection flag —
demonstrates an understanding of *why* the pattern is suspicious (elapsed
time vs. geographic distance), not just that a vendor feature exists to
catch it.

### 3.4 Supporting Query: Risk-Flagged Sign-Ins

```spl
index=entra sourcetype=entra_signin_log riskLevelDuringSignIn!="none"
| table createdDateTime, userPrincipalName, ipAddress, location.city, riskLevelDuringSignIn, riskState
| sort -createdDateTime
```

Confirms all three risk-flagged sign-in events, their risk level, and
their remediation state — useful as a standing triage query for any future
sign-in activity landing in this index.

### 3.5 Response & Disposition

Using **Entra ID Protection → Risky users → John Doe**, the flagged risk
was investigated and formally **dismissed** rather than confirmed as
compromise, with the following reasoning documented as part of the
analyst decision:

> Verified benign — sign-in originated from a known commercial VPN service
> (Surfshark) used deliberately for lab testing purposes, not indicative of
> account compromise.

The dismissal is reflected in the account's risk timeline (Actor: Admin,
11:29 AM), immediately following the 11:20 AM detection. This distinction
matters operationally: not every flagged detection represents an actual
threat, and treating VPN-originated traffic as automatic compromise would
generate unnecessary noise and alert fatigue in a real environment with
legitimate corporate VPN or remote-work traffic. A real SOC playbook for
this detection type should incorporate awareness of sanctioned VPN
services/exit-node ranges to reduce false-positive volume.

---

## 4. Scenario B: Over-Permissioned Application Registration

### 4.1 Finding

The `svc-automation` app registration was granted the following Microsoft
Graph permission:

| API | Permission | Type | Admin Consent | Granted By |
|---|---|---|---|---|
| Microsoft Graph | `User.Read.All` | Application | Yes | An administrator |

This permission allows the application to read **every user's full
profile in the tenant**, non-interactively, without any signed-in user
context — a tenant-wide, standing capability. The grant was admin-consented
once and has no expiration, no attached owner-review requirement, and no
scheduled re-certification.

### 4.2 Why This Matters

This configuration mirrors a real-world attack pattern known as an
**illicit consent grant**: an attacker convinces (or tricks) an
administrator into consenting to a malicious application's broad Graph
permissions. Once consented, the attacker's app can use its own client
credentials to pull data indefinitely — no user password is ever needed,
no MFA prompt is ever triggered, and the access persists silently until
someone specifically goes looking for it during an app permissions audit.

The **Enterprise Applications → Permissions** view for `svc-automation`
confirms exactly the kind of audit trail a real reviewer would examine:
permission scope, grant type (Admin consent), and the granting principal
("An administrator") — but nothing in the tenant natively flags that this
grant has gone unreviewed since creation. That absence of a built-in
staleness control is itself the core finding of this scenario.

### 4.3 Comparison to the On-Prem Kerberoasting Lab

This finding is the direct cloud-identity counterpart to the `svc-sql`
service account finding in the companion Kerberoasting lab: in both cases,
a **non-human identity was granted standing, broad-scope access with no
periodic review**, in two entirely different identity systems (on-prem
Active Directory vs. Entra ID). The underlying access-governance failure
is the same regardless of platform — which is the central thesis this
two-lab portfolio is built to demonstrate.

---

# Part B — Root Cause & IAM Remediation

## 5. Root Cause Analysis

| Finding | Root Cause |
|---|---|
| Scenario A — sign-in from anomalous location succeeded without additional friction | No risk-based Conditional Access policy was actively enforcing (report-only mode) at the time of the test sign-ins; a fully "before" state was preserved deliberately to demonstrate the gap a live policy would close |
| Scenario A — Atypical travel detection did not fire | New/low-history account with insufficient sign-in baseline; detection model limitation, not a misconfiguration |
| Scenario B — `svc-automation` has standing broad API access | Application permission was admin-consented once with no expiration and no attached access-review policy |

## 6. Remediation Recommendations

1. **Enable risk-based Conditional Access enforcement.** The
   `Risk-Based - Require MFA on Medium+ Sign-In Risk` policy, currently in
   report-only mode, should be switched to **On** following validation of
   its report-only evaluation history. This would have required additional
   authentication on the flagged sign-ins in Scenario A regardless of
   whether the underlying risk detection type was Atypical travel or
   Anonymous IP address.

2. **Move standing privileged roles to PIM-eligible, not active.** This
   lab already demonstrates the fix directly: `asmith`'s Security Reader
   role is assigned as PIM-eligible with a bounded one-year window and
   requires justification at activation, rather than being a standing
   active assignment. A compromised `asmith` credential is significantly
   less valuable to an attacker under this model, since the privileged
   role isn't usable without a deliberate, logged activation step.

3. **Scope `svc-automation`'s permission to the minimum required.**
   `User.Read.All` should be replaced with a narrower permission if the
   application's actual use case doesn't require tenant-wide user read
   access (e.g., a scoped application permission, or delegated permissions
   tied to a specific signed-in context if interactivity is acceptable).

4. **Attach a periodic access review to all application permission
   grants**, using **Entra ID → Identity Governance → Access Reviews**.
   Recurring review cycles (e.g., quarterly) would surface exactly this
   kind of stale, broad-scope grant before it becomes a real exposure.

5. **Set expiring client secrets with a documented rotation cadence** for
   all non-human identities, rather than long-lived or non-expiring
   credentials.

6. **Establish organizational awareness of sanctioned VPN/remote-access
   ranges** to reduce false-positive volume on Anonymous IP address
   detections going forward, improving analyst signal-to-noise ratio for
   this detection type specifically.

---

## 7. MITRE ATT&CK Mapping

| Technique | ID | How It Maps |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Legitimate `jdoe` credentials used from an anomalous location/IP, consistent with account-takeover-style activity even though this instance was benign VPN usage |
| Account Manipulation: Additional Cloud Roles | T1098.003 | Demonstrated as a **prevented** technique — PIM eligible-not-active assignment for `asmith` directly closes the standing-privileged-role gap this technique depends on |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | `svc-automation`'s standing, broad-scope, admin-consented Graph permission mirrors the illicit-consent-grant pattern that enables token-based access without further authentication |

---

## 8. Lessons Learned / Operational Notes

Several real troubleshooting issues came up during this build and are
documented here rather than smoothed over, consistent with the approach
taken in the companion SIEM and Kerberoasting labs:

- **Microsoft 365 Developer Program eligibility gate.** The free instant
  E5 sandbox path was not available for this account; the lab pivoted to
  provisioning a bare Entra ID tenant via Azure and adding a **Microsoft
  Entra ID P2 Managed Trial** (30-day) directly through the M365 Admin
  Center's Purchase Services catalog. This is a currently realistic
  obstacle for anyone building an Entra lab without an existing Visual
  Studio subscription, worth noting for future reference.
- **Portal/account fragmentation.** License and billing management is only
  available through the M365 Admin Center, not the Entra admin center —
  and the M365 Admin Center requires a native tenant account rather than
  the personal Microsoft account originally used to provision the tenant
  via Azure. A dedicated native admin account had to be created
  specifically to complete licensing.
- **Wrong application credentials in `.env`.** An initial pipeline run
  failed with `AADSTS700016` (application not found in directory) — the
  root cause was an incorrectly copied Client ID, pulled from the wrong
  browser tab/app registration. Resolved by re-verifying the Client ID
  directly against the `entra-log-shipper` app's Overview page rather than
  trusting a value copied earlier in the session.
- **Firewall blocking the Splunk HEC listener.** The pipeline's forward
  step failed with a connection timeout to the Splunk VM on port 8088,
  despite basic network reachability (ICMP ping) succeeding. Root cause
  was `ufw` blocking the port on the Splunk VM itself — resolved with
  `sudo ufw allow 8088/tcp`. This is a useful reminder that ICMP
  reachability does not confirm TCP port-level reachability, a distinction
  worth checking early rather than assuming a full networking-stack
  failure.
- **Identity Protection default filters hid real detections.** The
  **Risk detections** report defaults to filtering by risk *state* ("At
  risk," "Confirmed compromise"), which silently excluded detections that
  had already been auto-remediated or existed in other states. Clearing
  that filter was necessary to see the full detection history — a good
  reminder that default report filters in any SIEM/security console can
  create false negatives if not deliberately reviewed.

---

## Appendix: SPL Queries Used

**Risk-flagged sign-ins:**
```spl
index=entra sourcetype=entra_signin_log riskLevelDuringSignIn!="none"
| table createdDateTime, userPrincipalName, ipAddress, location.city, riskLevelDuringSignIn, riskState
| sort -createdDateTime
```

**Manually built impossible-travel detection:**
```spl
index=entra sourcetype=entra_signin_log
| eval city=coalesce('location.city',"unknown")
| sort 0 userPrincipalName, createdDateTime
| streamstats current=f last(city) as prev_city, last(createdDateTime) as prev_time by userPrincipalName
| where isnotnull(prev_city) AND city!=prev_city
| eval minutes_between=round((strptime(createdDateTime,"%Y-%m-%dT%H:%M:%S%Z") - strptime(prev_time,"%Y-%m-%dT%H:%M:%S%Z"))/60, 1)
| where minutes_between < 120
| table userPrincipalName, prev_city, city, minutes_between, createdDateTime
```

## Appendix: Log Pipeline

Sign-in logs were pulled from Microsoft Graph (`auditLogs/signIns`) using
an app-only (client credentials) OAuth flow and forwarded to Splunk via
HTTP Event Collector. Full source: [`pull_and_forward.py`](pull_and_forward.py)
in this repository.

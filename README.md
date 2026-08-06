# Microsoft Entra ID IAM Lab — Conditional Access, PIM & Risky Sign-In Detection

A self-built Entra ID (Azure AD) lab demonstrating cloud identity and access management, risk-based detection, and privileged access governance. Built as the cloud-identity companion to [ad-iam-kerberoasting-lab](https://github.com/BWhite-Sec/ad-iam-kerberoasting-lab), to demonstrate that detection engineering and access governance need to be understood together — on-prem and cloud alike — not siloed by platform.

## Overview

This project provisions a real Microsoft Entra ID P2 tenant, configures Conditional Access and Privileged Identity Management (PIM), simulates two realistic attack/misconfiguration scenarios, builds detections in Splunk against real Microsoft Graph data, and documents findings in a two-part incident report (SOC detection + IAM root-cause remediation).

**What this demonstrates:**

• Standing up Conditional Access policies (baseline MFA + risk-based adaptive), validated in report-only mode before enforcement
• Configuring Privileged Identity Management with eligible-not-active role assignment and just-in-time activation
• Building a Microsoft Graph API to Splunk log pipeline from scratch (OAuth client-credentials flow, HTTP Event Collector forwarding)
• Writing detection logic in SPL against real Entra sign-in log data, including a manually-built impossible-travel correlation query
• Reviewing and reasoning about an over-permissioned application registration (illicit-consent-grant pattern)
• Mapping findings to MITRE ATT&CK's cloud-identity techniques
• Documenting real environment/tooling friction as part of the process, not smoothing it out of the final write-up

## Architecture

Tenant: brandondevwhiteoutlook.onmicrosoft.com

• Users jdoe (Finance) and asmith (IT-Admins) sign in interactively; sign-in events are captured by Microsoft Graph (auditLogs/signIns).
• svc-automation (User.Read.All, intentionally over-permissioned) is the Scenario B finding, not part of the log pipeline.
• entra-log-shipper (AuditLog.Read.All, Directory.Read.All) authenticates via OAuth client-credentials flow and pulls sign-in logs from Graph.
• A Python script forwards each event to Splunk Enterprise via HTTP Event Collector, landing in index=entra.

**Stack:**

| Component | Details |
|---|---|
| Identity tenant | Microsoft Entra ID, P2 (30-day Managed Trial) |
| Conditional Access | Baseline MFA policy + risk-based adaptive MFA policy (report-only) |
| Privileged access | PIM eligible assignment (Security Reader to asmith) |
| Log pipeline | Python 3, requests, Microsoft Graph client-credentials OAuth flow |
| SIEM | Splunk Enterprise (Ubuntu Server, VirtualBox) — indexer shared with splunk-siem-lab |

## Repo Structure

• README.md
• docs/ (Incident report: two-part SOC + IAM write-up)
• detections/ (SPL detection queries)
• scripts/ (Graph API to Splunk pipeline, Python)
• screenshots/ (Evidence from Entra admin center and Splunk)
• configs/ (Sanitized environment notes)

## Scenarios

| Scenario | Description | Detection |
|---|---|---|
| A — Implausible-travel sign-in | Legitimate account signs in from two distant geographies within an implausible time window (VPN-simulated) | Identity Protection (Anonymous IP address) plus manually-built Splunk correlation query |
| B — Over-permissioned application | Service app registration granted broad, standing, admin-consented Graph permission with no review cadence | Manual review via Enterprise Applications to Permissions (illicit-consent-grant pattern) |

## Detections

| Detection | Purpose | File |
|---|---|---|
| Risk-flagged sign-ins | Surfaces any sign-in with a non-none risk level | detections/risky_signins.spl |
| Manual impossible-travel correlation | Independently validates travel-time/geography anomalies without relying on Identity Protection's built-in model | detections/impossible_travel.spl |

See docs/entra-id-iam-lab-incident-report.md for the full two-part write-up — SOC-side detection findings in Part A, IAM root-cause analysis and remediation recommendations in Part B.

## Log Pipeline

Sign-in logs are pulled from Microsoft Graph (auditLogs/signIns) using an app-only (client credentials) OAuth flow, via a dedicated entra-log-shipper app registration scoped to AuditLog.Read.All and Directory.Read.All — kept separate from svc-automation, which represents the intentionally over-permissioned finding rather than legitimate tooling. Events are forwarded to Splunk via HTTP Event Collector.

See scripts/pull_and_forward.py.

## Key Technical Notes

Real environment friction worth calling out (documented in full in the incident report):

• M365 Developer Program eligibility gate: the free instant E5 sandbox wasn't available for this account, requiring a pivot to provisioning a bare Entra ID tenant via Azure plus a standalone Entra ID P2 Managed Trial through the M365 Admin Center's purchase catalog.
• Wrong application credentials: an initial pipeline run failed with AADSTS700016 due to a Client ID copied from the wrong app registration tab — resolved by re-verifying directly against the correct app's Overview page.
• Firewall, not networking: the pipeline's Splunk forward step timed out despite successful ICMP reachability to the Splunk VM — root cause was ufw blocking port 8088 on the VM itself, a reminder that ping success doesn't confirm TCP port-level reachability.
• Default report filters hiding real data: Identity Protection's Risk detections report defaults to filtering by risk state in a way that silently excluded already-remediated detections, requiring the filter to be manually cleared to see the full picture.

## MITRE ATT&CK Mapping

| Technique | ID | Notes |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Legitimate credentials used from an anomalous location/IP |
| Account Manipulation: Additional Cloud Roles | T1098.003 | Demonstrated as a prevented technique via PIM eligible-not-active design |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | Over-permissioned svc-automation app mirrors the illicit-consent-grant pattern |

## Next Steps / Roadmap

• Add a scheduled Access Review on svc-automation's permissions and document the review cycle
• Switch the risk-based Conditional Access policy from report-only to enforced, and capture a before/after sign-in comparison
• Cross-reference this lab's svc-automation finding directly against the svc-sql finding in ad-iam-kerberoasting-lab in a short comparison write-up

## Author

Brandon White — [LinkedIn](https://www.linkedin.com/in/brandon-white-b62701177) — [GitHub](https://github.com/BWhite-Sec)

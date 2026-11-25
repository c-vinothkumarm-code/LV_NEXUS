"""LV NEXUS compliance policy library.

Each policy is one checkable control written in our own words, mapped to the framework requirements it supports.
Framework texts are not reproduced: references are identifiers only (ISO/IEC, SOC 2 and CSA texts are licensed; read
the official documents for wording). Obligation classes are kept apart on purpose:

- legal      : binding on LatentView as a body corporate in India today (CERT-In Directions, 28 Apr 2022, s.70B(6) IT Act,
               in force since 27 Jun 2022).
- legal_upcoming : notified law whose obligations start later (DPDP Act 2023 with the DPDP Rules 2025 notified
               13 Nov 2025; Rules 3 and 5-16, including security safeguards, breach intimation and log retention,
               apply 18 months after notification, i.e. from 13 May 2027). Confirm dates with legal counsel.
- voluntary  : certifiable / attestable frameworks adopted by choice (ISO/IEC 27001, 27017, 27018, SOC 2, NIST CSF 2.0,
               CIS Controls and Benchmarks, CSA CCM, OWASP).
- internal   : LatentView's own policy settings in this platform.

A passing score is a statement about the checks run over collected cloud data. It is not a certification or legal
opinion."""
from __future__ import annotations

from dataclasses import dataclass, field

LEGAL, UPCOMING, VOLUNTARY, INTERNAL = "legal", "legal_upcoming", "voluntary", "internal"

FRAMEWORKS: dict[str, dict] = {
    "certin": {"name": "CERT-In Directions 2022", "version": "28 Apr 2022 (s.70B(6) IT Act)", "obligation": LEGAL,
               "authority": "Indian Computer Emergency Response Team (MeitY)",
               "note": "Applies to body corporates in India since 27 Jun 2022: report listed incidents within 6 hours, designate a "
                       "point of contact, keep ICT logs 180 days in India, synchronise clocks with NIC / NPL NTP."},
    "dpdp": {"name": "DPDP Act 2023 & DPDP Rules 2025", "version": "Rules notified 13 Nov 2025", "obligation": UPCOMING,
             "authority": "Ministry of Electronics and IT; Data Protection Board of India",
             "note": "Security safeguards (Rule 6), breach intimation incl. 72-hour report to the Board (Rule 7) and one-year log "
                     "retention (Rule 8(3)) apply from 13 May 2027. Prepare now; confirm with legal counsel."},
    "iso27001": {"name": "ISO/IEC 27001:2022", "version": "2022 Annex A", "obligation": VOLUNTARY, "authority": "ISO / IEC",
                 "note": "Information security management system. References are Annex A control numbers."},
    "iso27017": {"name": "ISO/IEC 27017:2015", "version": "2015", "obligation": VOLUNTARY, "authority": "ISO / IEC",
                 "note": "Cloud security controls (cloud-specific CLD controls and cloud guidance on ISO/IEC 27002)."},
    "iso27018": {"name": "ISO/IEC 27018:2019", "version": "2019", "obligation": VOLUNTARY, "authority": "ISO / IEC",
                 "note": "Protection of PII in public clouds acting as PII processors."},
    "nist_csf": {"name": "NIST Cybersecurity Framework 2.0", "version": "2.0 (Feb 2024)", "obligation": VOLUNTARY, "authority": "NIST",
                 "note": "References are CSF 2.0 subcategories."},
    "cis": {"name": "CIS Critical Security Controls v8 & CIS Benchmarks", "version": "v8.1", "obligation": VOLUNTARY,
            "authority": "Center for Internet Security", "note": "Safeguard numbers; cloud benchmark results also arrive as provider findings."},
    "soc2": {"name": "SOC 2 Trust Services Criteria", "version": "2017 (rev. 2022)", "obligation": VOLUNTARY, "authority": "AICPA",
             "note": "Common Criteria (CC) and Availability (A) references."},
    "csa_ccm": {"name": "CSA Cloud Controls Matrix", "version": "v4", "obligation": VOLUNTARY, "authority": "Cloud Security Alliance",
                "note": "Control IDs from CCM v4 domains."},
    "owasp": {"name": "OWASP Top 10 & API Security Top 10", "version": "2021 / API 2023", "obligation": VOLUNTARY, "authority": "OWASP",
              "note": "Applied to LV NEXUS itself and to exposed cloud services."},
    "lv_internal": {"name": "LatentView internal cloud policy", "version": "platform settings", "obligation": INTERNAL,
                    "authority": "LatentView Information Security", "note": "Thresholds and conventions set by LatentView in this platform."},
}

DOMAINS = {
    "iam": "Identity & access management", "mfa": "MFA & privileged access", "least_privilege": "Least privilege",
    "encryption": "Encryption", "exposure": "Public exposure & network", "logging": "Logging, monitoring & retention",
    "vuln": "Vulnerability & configuration", "backup": "Backup & disaster recovery", "privacy": "Data protection & privacy",
    "incident": "Incident detection & response", "platform": "Platform security (LV NEXUS)",
}
SEVERITY_WEIGHT = {"Critical": 10, "High": 5, "Medium": 3, "Low": 1}


@dataclass(frozen=True)
class Policy:
    key: str
    title: str
    domain: str
    severity: str
    check: str                      # function name in checks.py
    why: str
    remediation: str
    refs: dict[str, list[str]]
    params: dict = field(default_factory=dict)
    kind: str = "automated"         # automated | attestation
    clouds: tuple[str, ...] = ("aws", "azure", "gcp")


P = Policy
POLICIES: list[Policy] = [
    # ---------------------------------------------------------------- IAM / MFA / privileged
    P("IAM-01", "Privileged roles held by a small, named group", "mfa", "High", "privileged_holders",
      "Every extra Owner / administrator multiplies the damage one stolen account can do.",
      "Review the listed identities; remove standing admin rights not needed daily and use just-in-time (PIM) elevation.",
      {"iso27001": ["A.8.2", "A.5.18"], "iso27017": ["9.2.3 (cloud guidance)"], "nist_csf": ["PR.AA-05"], "cis": ["5.4", "6.8"],
       "soc2": ["CC6.1", "CC6.3"], "csa_ccm": ["IAM-09", "IAM-10"], "dpdp": ["Rule 6(1)(b) access control"], "lv_internal": ["max privileged per scope"]},
      params={"max_privileged": 5}),
    P("IAM-02", "No privileged access for guest or external accounts", "mfa", "High", "guest_privileged",
      "Guest accounts are managed by another organisation; LatentView cannot enforce their MFA or offboarding.",
      "Replace guest admin assignments with LatentView-managed accounts or time-bound PIM eligibility.",
      {"iso27001": ["A.5.19", "A.8.2"], "nist_csf": ["PR.AA-05"], "cis": ["5.4"], "soc2": ["CC6.2"], "csa_ccm": ["IAM-09"]}, clouds=("azure",)),
    P("IAM-03", "Disabled or departed identities hold no cloud access", "iam", "High", "disabled_with_access",
      "Access that outlives the person is a standing backdoor and an audit finding in every framework.",
      "Remove the listed role assignments (leaver process) and confirm in the next access inventory.",
      {"iso27001": ["A.5.18", "A.5.16"], "nist_csf": ["PR.AA-01"], "cis": ["5.3", "6.2"], "soc2": ["CC6.2", "CC6.3"], "csa_ccm": ["IAM-07"],
       "dpdp": ["Rule 6(1)(b) access control"]}),
    P("IAM-04", "Dormant privileged accounts removed (90 days)", "iam", "Medium", "dormant_privileged",
      "Unused admin accounts are not watched by their owners and are a common entry point.",
      "Disable or remove privileged accounts with no sign-in for 90 days; re-grant on request.",
      {"iso27001": ["A.5.18"], "nist_csf": ["PR.AA-05"], "cis": ["5.3"], "soc2": ["CC6.2"], "csa_ccm": ["IAM-08"]}, params={"days": 90}, clouds=("azure",)),
    P("IAM-05", "MFA enforced for every user and administrator", "mfa", "Critical", "finding_mfa",
      "Password-only sign-in is the most exploited weakness in cloud breaches.",
      "Enforce MFA through Conditional Access / IAM policy for all users; block legacy authentication.",
      {"iso27001": ["A.8.5", "A.5.17"], "iso27017": ["9.4.2 (cloud guidance)"], "nist_csf": ["PR.AA-03"], "cis": ["6.3", "6.4", "6.5"],
       "soc2": ["CC6.1"], "csa_ccm": ["IAM-14"], "owasp": ["A07:2021"], "dpdp": ["Rule 6(1)(b) access control"]}),
    P("IAM-06", "Root / global-admin elevation not used for routine work", "mfa", "High", "root_usage",
      "Root and elevated global-admin sessions bypass normal guardrails and must be exceptional and approved.",
      "Investigate each listed use; keep root credentials sealed with hardware MFA; require approval for elevation.",
      {"iso27001": ["A.8.2"], "nist_csf": ["PR.AA-05", "DE.CM-03"], "cis": ["5.4"], "soc2": ["CC6.1"], "csa_ccm": ["IAM-10"]}, params={"days": 30}),
    P("IAM-07", "Application secrets and certificates expire and are rotated", "iam", "Medium", "app_credentials",
      "Long-lived or expired app credentials are hard to track and often leaked in code.",
      "Use certificates or managed identities; set secret lifetimes of 12 months or less; remove expired credentials.",
      {"iso27001": ["A.5.17", "A.8.24"], "nist_csf": ["PR.AA-01"], "cis": ["5.2"], "soc2": ["CC6.1"], "csa_ccm": ["IAM-02", "CEK-12"]},
      params={"max_days": 365}, clouds=("azure",)),
    P("IAM-08", "Workload identities do not hold Owner rights", "least_privilege", "High", "workload_owner",
      "A service principal or role with Owner can change access itself; compromise of the workload means full control.",
      "Replace Owner with the narrowest built-in role the workload needs, scoped to its resource group.",
      {"iso27001": ["A.8.2", "A.5.15"], "iso27017": ["CLD.12.1.5"], "nist_csf": ["PR.AA-05"], "cis": ["6.8"], "soc2": ["CC6.3"],
       "csa_ccm": ["IAM-05"], "owasp": ["A01:2021", "API5:2023"]}),
    # ---------------------------------------------------------------- encryption
    P("ENC-01", "Data encrypted at rest", "encryption", "High", "finding_encryption_rest",
      "Unencrypted disks, buckets and databases expose data if media, snapshots or backups leak.",
      "Enable provider encryption (customer-managed keys for regulated data) on the listed resources.",
      {"iso27001": ["A.8.24"], "iso27017": ["10.1.1 (cloud guidance)"], "iso27018": ["Annex A: encryption of PII"], "nist_csf": ["PR.DS-01"],
       "cis": ["3.11"], "soc2": ["CC6.1"], "csa_ccm": ["CEK-03"], "dpdp": ["Rule 6(1)(a) encryption / masking"], "owasp": ["A02:2021"]}),
    P("ENC-02", "Data encrypted in transit (TLS 1.2+, HTTPS only)", "encryption", "High", "finding_encryption_transit",
      "Plain HTTP or old TLS lets traffic be read or altered on the network.",
      "Require HTTPS / secure transfer and minimum TLS 1.2 on the listed services.",
      {"iso27001": ["A.8.24", "A.8.20"], "iso27018": ["Annex A: encryption of PII over public networks"], "nist_csf": ["PR.DS-02"], "cis": ["3.10"],
       "soc2": ["CC6.7"], "csa_ccm": ["CEK-03"], "dpdp": ["Rule 6(1)(a) encryption / masking"], "owasp": ["A02:2021"]}),
    P("ENC-03", "Encryption keys protected (rotation, soft-delete, purge protection)", "encryption", "Medium", "finding_keys",
      "A deleted or never-rotated key can make data unrecoverable or keep a leaked key valid.",
      "Turn on key rotation and Key Vault soft-delete / purge protection; restrict key administrators.",
      {"iso27001": ["A.8.24"], "nist_csf": ["PR.DS-01"], "cis": ["3.11"], "soc2": ["CC6.1"], "csa_ccm": ["CEK-10", "CEK-12"]}),
    # ---------------------------------------------------------------- exposure
    P("NET-01", "No admin ports (SSH / RDP / databases) open to the internet", "exposure", "Critical", "open_admin_ports",
      "Internet-reachable SSH, RDP and database ports are scanned continuously and are a top ransomware entry point.",
      "Close the listed ports to 0.0.0.0/0; use Bastion / VPN / just-in-time access instead.",
      {"iso27001": ["A.8.20", "A.8.22"], "iso27017": ["CLD.13.1.4"], "nist_csf": ["PR.IR-01"], "cis": ["4.4", "12.2"], "soc2": ["CC6.6"],
       "csa_ccm": ["IVS-03"], "owasp": ["A05:2021"]}),
    P("NET-02", "Storage is not publicly accessible", "exposure", "Critical", "finding_public_storage",
      "Public buckets and containers are the most common cause of cloud data leaks.",
      "Disable public / anonymous access on the listed storage; share data with signed, time-limited links.",
      {"iso27001": ["A.8.3", "A.5.15"], "iso27018": ["Annex A: PII disclosure controls"], "nist_csf": ["PR.DS-01", "PR.AA-05"], "cis": ["3.3"],
       "soc2": ["CC6.1"], "csa_ccm": ["DSP-17"], "dpdp": ["s.8(5) reasonable security safeguards"], "owasp": ["A01:2021"]}),
    P("NET-03", "Network rules restrict inbound traffic", "exposure", "High", "finding_network",
      "Wide-open security groups and firewalls remove the first line of defence.",
      "Replace any-source rules with specific source ranges; review NSG / security group findings listed.",
      {"iso27001": ["A.8.20", "A.8.21"], "iso27017": ["CLD.9.5.1"], "nist_csf": ["PR.IR-01"], "cis": ["4.4", "13.4"], "soc2": ["CC6.6"],
       "csa_ccm": ["IVS-03"]}),
    P("NET-04", "Managed databases are not publicly reachable", "exposure", "High", "finding_db_exposure",
      "Databases reachable from the internet are brute-forced and exfiltrated directly.",
      "Disable public network access; use private endpoints; remove 0.0.0.0-255.255.255.255 firewall rules.",
      {"iso27001": ["A.8.20", "A.8.3"], "nist_csf": ["PR.IR-01"], "cis": ["12.2"], "soc2": ["CC6.6"], "csa_ccm": ["IVS-03"], "owasp": ["A05:2021"]}),
    # ---------------------------------------------------------------- logging
    P("LOG-01", "Activity logs collected from every account, subscription and project", "logging", "Critical", "activity_collected",
      "An account without collected activity logs is invisible to detection and to incident investigation.",
      "Fix the listed collection failure (System health shows the exact permission) so activity is read every 5 minutes.",
      {"certin": ["Direction (iv): enable logs of all ICT systems"], "iso27001": ["A.8.15", "A.8.16"], "iso27017": ["CLD.12.4.5"],
       "nist_csf": ["PR.PS-04", "DE.CM-09"], "cis": ["8.2"], "soc2": ["CC7.2"], "csa_ccm": ["LOG-07", "LOG-08"], "owasp": ["A09:2021"],
       "dpdp": ["Rule 6(1)(c) logs and monitoring"]}),
    P("LOG-02", "Logs retained for 180 days (CERT-In) and one year (DPDP)", "logging", "Critical", "log_retention",
      "CERT-In requires a rolling 180 days of ICT logs kept in India; DPDP Rule 8(3) requires one year from 13 May 2027.",
      "Keep AUDIT_RETENTION_DAYS at 365 or more and host the LV NEXUS database in India.",
      {"certin": ["Direction (iv): 180-day log retention in India"], "dpdp": ["Rule 8(3) one-year retention of logs"], "iso27001": ["A.8.15"],
       "cis": ["8.10"], "soc2": ["CC7.2"], "csa_ccm": ["LOG-02"]}, clouds=("platform",)),
    P("LOG-03", "Cloud-native threat detection enabled", "logging", "High", "security_service_on",
      "Defender for Cloud, Security Hub and Security Command Center are the providers' own detection; without them findings stay hidden.",
      "Enable the provider security service on the listed scopes and let the daily findings sync succeed.",
      {"iso27001": ["A.8.16"], "nist_csf": ["DE.CM-09", "ID.RA-01"], "cis": ["13.1"], "soc2": ["CC7.1"], "csa_ccm": ["LOG-03"]}),
    P("LOG-04", "Diagnostic and network flow logging enabled on resources", "logging", "Medium", "finding_logging",
      "Resource-level logs are needed to reconstruct what an attacker touched.",
      "Turn on diagnostic settings / flow logs for the listed resources and send them to the central workspace.",
      {"certin": ["Direction (iv): enable logs of all ICT systems"], "iso27001": ["A.8.15"], "nist_csf": ["PR.PS-04"], "cis": ["8.2", "13.6"],
       "soc2": ["CC7.2"], "csa_ccm": ["LOG-07"]}),
    P("LOG-05", "Clocks synchronised with NIC / NPL time servers", "logging", "Medium", "attestation",
      "CERT-In requires ICT clocks to follow the NTP servers of NIC or NPL (or servers traceable to them) so incident timelines line up.",
      "Point domain controllers and servers to time.nic.in / samay1.nic.in (or NPL); attest with a screenshot of the NTP configuration.",
      {"certin": ["Direction (i): clock synchronisation"], "iso27001": ["A.8.17"], "csa_ccm": ["LOG-06"]}, kind="attestation", clouds=("platform",)),
    # ---------------------------------------------------------------- vulnerability & configuration
    P("VUL-01", "Critical and high findings fixed within SLA", "vuln", "High", "sla_overdue",
      "Known, unfixed weaknesses past their deadline are what auditors and attackers look for first.",
      "Assign an owner to each overdue finding and fix it, or record an approved exception with an expiry.",
      {"iso27001": ["A.8.8"], "nist_csf": ["ID.RA-01", "PR.PS-02"], "cis": ["7.7"], "soc2": ["CC7.1"], "csa_ccm": ["TVM-08", "TVM-10"]}),
    P("VUL-02", "Operating systems and images patched", "vuln", "High", "finding_patching",
      "Missing security updates are the cause of most server compromises.",
      "Apply the missing updates on the listed machines; enable automatic patching (Update Manager / SSM Patch Manager / OS Config).",
      {"iso27001": ["A.8.8", "A.8.19"], "iso27017": ["CLD.9.5.2"], "nist_csf": ["PR.PS-02"], "cis": ["7.3", "7.4"], "soc2": ["CC7.1"], "csa_ccm": ["TVM-09"]}),
    P("VUL-03", "Endpoint / malware protection on servers", "vuln", "Medium", "finding_endpoint",
      "Servers without endpoint protection miss commodity malware and ransomware.",
      "Deploy Defender for Endpoint / GuardDuty runtime / the corporate EDR on the listed machines.",
      {"iso27001": ["A.8.7"], "nist_csf": ["DE.CM-09"], "cis": ["10.1"], "soc2": ["CC6.8"], "csa_ccm": ["TVM-02"]}),
    P("VUL-04", "Provider configuration benchmark failures closed", "vuln", "Medium", "benchmark_failures",
      "CIS Foundations and provider benchmarks catch most cloud misconfigurations.",
      "Work through the failing benchmark controls listed; fix or record an approved exception.",
      {"cis": ["CIS Benchmarks (AWS / Azure / GCP Foundations)"], "iso27001": ["A.8.9"], "nist_csf": ["PR.PS-01"], "soc2": ["CC7.1"], "csa_ccm": ["IVS-04"]}),
    # ---------------------------------------------------------------- backup & DR
    P("BCK-01", "Virtual machines and data stores backed up", "backup", "High", "finding_backup",
      "Without backups a ransomware attack or deletion is permanent.",
      "Enable Azure Backup / AWS Backup / GCP Backup and DR for the listed resources with a retention that meets the business need.",
      {"iso27001": ["A.8.13"], "iso27017": ["12.3.1 (cloud guidance)"], "nist_csf": ["PR.DS-11"], "cis": ["11.2"], "soc2": ["A1.2"], "csa_ccm": ["BCR-08"],
       "dpdp": ["Rule 6(1)(e) backups for continued processing"]}),
    P("BCK-02", "Disaster recovery plan tested in the last 12 months", "backup", "High", "attestation",
      "An untested recovery plan usually fails on the day it is needed.",
      "Run a restore / failover test, record RTO and RPO achieved, and attest with the test report.",
      {"iso27001": ["A.5.30", "A.5.29"], "nist_csf": ["RC.RP-01", "PR.IR-03"], "cis": ["11.5"], "soc2": ["A1.3"], "csa_ccm": ["BCR-06"]},
      kind="attestation", clouds=("platform",)),
    # ---------------------------------------------------------------- privacy
    P("DPP-01", "Data stores carry a data-classification tag", "privacy", "Medium", "classification_tags",
      "You cannot protect personal data you have not identified; DPDP safeguards and breach scoping start from it.",
      "Tag every storage account, bucket and database with data-classification (public / internal / confidential / personal).",
      {"dpdp": ["s.8(5) safeguards (scope of personal data)"], "iso27001": ["A.5.12", "A.5.13"], "iso27018": ["Annex A: PII inventory"],
       "nist_csf": ["ID.AM-07"], "cis": ["3.2", "3.7"], "soc2": ["C1.1"], "csa_ccm": ["DSP-04"], "lv_internal": ["tag key data-classification"]},
      params={"tag_key": "data-classification"}),
    P("DPP-02", "Personal data stored only in approved regions", "privacy", "High", "pii_regions",
      "DPDP s.16 lets the Government restrict transfers to notified countries; client contracts often require India-only storage.",
      "Move or replicate the listed personal-data stores to an approved region, or record the approved transfer basis.",
      {"dpdp": ["s.16 cross-border transfer"], "iso27018": ["Annex A: geographical location of PII"], "csa_ccm": ["DSP-19"],
       "lv_internal": ["approved regions"]}, params={"tag_key": "data-classification", "personal_values": ["personal", "pii", "sensitive"],
                                                  "approved_regions": ["centralindia", "southindia", "westindia", "ap-south-1", "ap-south-2",
                                                                       "asia-south1", "asia-south2"]}),
    P("DPP-03", "Personal-data breach notification procedure in place", "privacy", "High", "attestation",
      "DPDP Rule 7 requires informing affected people without delay and a detailed report to the Board within 72 hours (from 13 May 2027).",
      "Approve the breach runbook (who decides, Board and Data Principal templates, 72-hour clock) and attest with the approved document.",
      {"dpdp": ["s.8(6) breach intimation", "Rule 7"], "iso27018": ["Annex A: notification of a data breach involving PII"], "iso27001": ["A.5.24", "A.5.26"],
       "soc2": ["CC7.4"], "csa_ccm": ["SEF-07"]}, kind="attestation", clouds=("platform",)),
    # ---------------------------------------------------------------- incident
    P("IR-01", "Core SOC detection rules switched on", "incident", "High", "detection_rules",
      "Disabled detection rules mean privilege grants, logging changes and credential attacks go unnoticed.",
      "Re-enable the listed rules in Live audit > Rules, or document why each is off.",
      {"certin": ["Direction (ii): ability to notice reportable incidents"], "iso27001": ["A.8.16", "A.5.25"], "nist_csf": ["DE.AE-02", "DE.CM-03"],
       "cis": ["8.11", "13.1"], "soc2": ["CC7.2", "CC7.3"], "csa_ccm": ["LOG-05", "SEF-03"]},
      params={"rules": ["AUD-001", "AUD-010", "AUD-012", "AUD-015", "AUD-018", "AUD-019", "AUD-020", "AUD-024"]}, clouds=("platform",)),
    P("IR-02", "High-risk detections triaged within 6 hours", "incident", "Critical", "triage_6h",
      "CERT-In requires reportable incidents to be reported within 6 hours of noticing them; that is only possible if triage starts at once.",
      "Assign and triage the listed cases now; decide whether each is CERT-In reportable and record the decision.",
      {"certin": ["Direction (ii): report within 6 hours"], "iso27001": ["A.5.25", "A.5.26"], "nist_csf": ["RS.MA-01", "RS.CO-02"], "cis": ["17.4"],
       "soc2": ["CC7.3", "CC7.4"], "csa_ccm": ["SEF-03"]}, params={"hours": 6}, clouds=("platform",)),
    P("IR-03", "Security alerts reach people (e-mail or Chat working)", "incident", "High", "alert_channels",
      "A detection nobody receives is the same as no detection.",
      "Configure SMTP_* and/or CHAT_WEBHOOK_URL and confirm the daily governance dashboard was delivered.",
      {"certin": ["Direction (ii): timely reporting"], "iso27001": ["A.5.24", "A.6.8"], "nist_csf": ["RS.CO-02"], "soc2": ["CC7.3"], "csa_ccm": ["SEF-08"]},
      clouds=("platform",)),
    P("IR-04", "CERT-In point of contact designated and current", "incident", "High", "attestation",
      "CERT-In sends all directions to the designated point of contact; changes must be notified.",
      "Name the point of contact, file the Annexure details with CERT-In, and attest with the acknowledgement.",
      {"certin": ["Direction (iii): point of contact"], "iso27001": ["A.5.5"], "nist_csf": ["GV.RR-02"], "cis": ["17.2"], "csa_ccm": ["SEF-08"]},
      kind="attestation", clouds=("platform",)),
    # ---------------------------------------------------------------- platform (LV NEXUS itself)
    P("APP-01", "LV NEXUS sign-in uses the corporate identity provider", "platform", "High", "app_sso",
      "Local or development sign-in has no MFA, no central offboarding and no conditional access.",
      "Set AUTH_MODE=google (or entra) and add users through the access registry.",
      {"owasp": ["A07:2021", "API2:2023"], "iso27001": ["A.8.5"], "nist_csf": ["PR.AA-03"], "soc2": ["CC6.1"]}, clouds=("platform",)),
    P("APP-02", "LV NEXUS secrets come from a vault in production", "platform", "High", "app_secrets",
      "Secrets in files are copied, backed up and leaked with them.",
      "Set AZURE_KEY_VAULT_URL and move the listed secrets into Key Vault before going live.",
      {"owasp": ["A05:2021", "API8:2023"], "iso27001": ["A.8.24", "A.5.17"], "soc2": ["CC6.1"], "csa_ccm": ["CEK-03"]}, clouds=("platform",)),
    P("APP-03", "LV NEXUS API protects against abuse (rate limits, sessions)", "platform", "Medium", "app_hardening",
      "Without rate limits and session timeouts an API is easier to brute-force and abuse.",
      "Keep RATE_LIMIT_PER_MINUTE and AUTH_RATE_LIMIT_PER_MINUTE above zero and SESSION_IDLE_MINUTES at 60 or less.",
      {"owasp": ["API4:2023", "A07:2021"], "iso27001": ["A.8.26"], "soc2": ["CC6.6"]}, clouds=("platform",)),
]
BY_KEY = {p.key: p for p in POLICIES}

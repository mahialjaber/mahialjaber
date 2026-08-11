<h1 align="center">Mahi Al Jaber</h1>

<p align="center">
  <b>SOC / Detection &amp; Response Analyst</b><br>
  Splunk &amp; SPL · AWS CloudTrail Threat Detection · Detection-as-Code
</p>

<p align="center">
  <a href="mailto:mahialjaber.dev@gmail.com">Email</a> ·
  <a href="#">LinkedIn</a> ·
  <a href="https://wa.me/8801893142872">WhatsApp</a>
</p>

---

I investigate alerts and write the detections that generate them.

My work sits at the intersection of two things most junior analysts keep separate: **SOC operations** (triage, enrichment, escalation, documentation) and **AWS telemetry** (CloudTrail, IAM, GuardDuty). I emulate real attacker techniques in a lab I built myself, capture the telemetry they produce, write detections for them in Sigma, and document the investigation the way a Tier 1 analyst documents a ticket.

Everything below links to evidence. Nothing here is a course completion.

**Open to:** entry-level SOC / Blue Team analyst and internship roles — remote worldwide, or relocation.

---

## Selected Investigations

Each case file follows the same structure: alert → what I checked and why → enrichment → verdict and confidence → escalation summary → recommended tuning. Including the ones I initially got wrong.

| Case | Trigger | ATT&CK | Verdict | Write-up |
|---|---|---|---|---|
| <!-- e.g. Impossible travel on service account --> | <!-- alert source --> | <!-- T1078.004 --> | <!-- TP / FP --> | [Read](#) |
| | | | | [Read](#) |
| | | | | [Read](#) |

<!--
FILL THIS IN FIRST. This table is the single most important thing on your profile.
Target: 15 rows within 30 days. Sources: CyberDefenders, Splunk BOTS, LetsDefend,
and your own lab. Delete this table only if you would rather not be hired.
-->

---

## Detection Engineering

Vendor-neutral Sigma rules, each with a documented threat model, tested false positives, and compiled SPL + KQL output.

**Repository:** [SOC-Detection-Rules](#) · *N rules · M ATT&CK techniques covered*

| Rule | Log Source | ATT&CK | FP Notes |
|---|---|---|---|
| <!-- rule title --> | <!-- windows/security, aws/cloudtrail --> | <!-- Txxxx --> | <!-- what tuning was needed --> |
| | | | |
| | | | |

Pipeline: rules validated and converted via `sigma-cli` in CI on every commit.

---

## AWS Threat Detection Lab

Self-built AWS environment where I emulate cloud attacker techniques, ship CloudTrail into Splunk, and build detections against the resulting telemetry.

| Technique Emulated | ATT&CK | Detection Built | Signal Used |
|---|---|---|---|
| IAM access key exfiltration &amp; reuse | T1552.001 | <!-- yes/link --> | CloudTrail |
| EC2 instance metadata credential theft | T1552.005 | | CloudTrail, VPC Flow |
| CloudTrail logging disabled | T1562.008 | | CloudTrail |
| Lambda backdoor persistence | T1546 | | CloudTrail |
| S3 mass object enumeration &amp; download | T1530 | | S3 Data Events |

**Repository:** [enterprise-threat-detection-soc-lab](https://github.com/mahialjaber/enterprise-threat-detection-soc-lab)

---

## Phishing Triage

Header and payload analysis workflow with automated enrichment — SPF/DKIM/DMARC evaluation, URL and attachment reputation, IOC extraction, analyst verdict.

**Repository:** [CLI-Threat-Analyzer](https://github.com/mahialjaber/CLI-Threat-Analyzer) · *N samples analyzed and documented*

---

## Toolchain

**SIEM &amp; Detection** — Splunk (SPL), Sigma, MITRE ATT&CK, Microsoft Sentinel (KQL)
**Endpoint &amp; Identity** — Sysmon, Windows Event Logs, Active Directory, PowerShell logging
**Cloud** — AWS CloudTrail, IAM, GuardDuty, CloudWatch, S3, VPC, Lambda
**Network** — Wireshark, TCP/IP, DNS, HTTP, packet analysis
**Automation** — Python, Bash, Git, REST APIs
**Frameworks** — MITRE ATT&CK, NIST SP 800-61, Cyber Kill Chain

---

## Currently

- Building out the detection rule library and investigation case files above
- Working toward Splunk Core Certified Power User
- Open to entry-level SOC roles and internships — [get in touch](mailto:mahialjaber.dev@gmail.com)

---

<p align="center">
  <img src="https://github-readme-stats.vercel.app/api?username=mahialjaber&show_icons=true&hide_border=true&theme=dark&hide=stars,issues" alt="GitHub stats" />
</p>

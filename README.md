<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0F6E56,1D9E75,5DCAA5&height=200&section=header&text=Mahi%20Al%20Jaber&fontSize=52&fontColor=ffffff&fontAlignY=38&desc=Detection%20%7C%20Response%20%7C%20Cloud%20Threat%20Detection&descAlignY=58&descSize=18&animation=fadeIn" width="100%"/>

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&pause=1200&color=1D9E75&center=true&vCenter=true&width=700&lines=Alert+Triage+%7C+Enrichment+%7C+Escalation;Sigma+Detections+%7C+Splunk+SPL+%7C+MITRE+ATT%26CK;AWS+CloudTrail+Threat+Detection;Open+to+Entry-Level+SOC+Roles+%26+Internships+%F0%9F%8C%8D" alt="Typing SVG" />

<br/>

<a href="mailto:mahialjaber.dev@gmail.com"><img src="https://img.shields.io/badge/Email-1D9E75?style=flat-square&logo=gmail&logoColor=white" alt="Email"/></a>
<a href="https://wa.me/8801893142872"><img src="https://img.shields.io/badge/WhatsApp-25D366?style=flat-square&logo=whatsapp&logoColor=white" alt="WhatsApp"/></a>
<a href="https://github.com/mahialjaber?tab=repositories"><img src="https://img.shields.io/badge/Projects-181717?style=flat-square&logo=github&logoColor=white" alt="Projects"/></a>

</div>

---

## 🛡️ What I Do

**I investigate alerts and write the detections that generate them.**

My work sits at the intersection of two things most junior analysts keep separate: **SOC operations** — triage, enrichment, escalation, documentation — and **AWS telemetry** — CloudTrail, IAM, GuardDuty. I emulate real attacker techniques in a lab I built myself, capture the telemetry they produce, write detections for them in Sigma, and document the investigation the way a Tier 1 analyst documents a ticket.

Everything below links to evidence. Nothing here is a course completion.

> **Open to:** entry-level SOC / Blue Team analyst and internship roles — remote worldwide, or relocation.

---

## 🔍 Selected Investigations

Each case file follows the same structure: **alert → what I checked and why → enrichment → verdict and confidence → escalation summary → recommended tuning.** Including the ones I initially got wrong.

| Case | Trigger | ATT&CK | Verdict | Write-up |
|---|---|---|---|---|
| <!-- e.g. Impossible travel on service account --> | <!-- alert source --> | <!-- T1078.004 --> | <!-- TP / FP --> | [Read](#) |
| | | | | [Read](#) |
| | | | | [Read](#) |

<!--
FILL THIS IN FIRST. This table is the single most important thing on your profile.
Target: 15 rows within 30 days. Sources: CyberDefenders, Splunk BOTS, LetsDefend,
and your own lab.
-->

---

## ⚙️ Detection Engineering

Vendor-neutral **Sigma** rules — each with a documented threat model, tested false positives, and compiled SPL + KQL output.

**Repository:** [SOC-Detection-Rules](#) · *N rules · M ATT&CK techniques covered*

| Rule | Log Source | ATT&CK | FP Notes |
|---|---|---|---|
| <!-- rule title --> | <!-- windows/security, aws/cloudtrail --> | <!-- Txxxx --> | <!-- tuning required --> |
| | | | |
| | | | |

Rules are validated and converted via `sigma-cli` in CI on every commit.

---

## ☁️ AWS Threat Detection Lab

Self-built AWS environment where I emulate cloud attacker techniques, ship CloudTrail into Splunk, and build detections against the resulting telemetry.

| Technique Emulated | ATT&CK | Detection | Signal |
|---|---|---|---|
| IAM access key exfiltration & reuse | T1552.001 | <!-- link --> | CloudTrail |
| EC2 instance metadata credential theft | T1552.005 | | CloudTrail, VPC Flow |
| CloudTrail logging disabled | T1562.008 | | CloudTrail |
| Lambda backdoor persistence | T1546 | | CloudTrail |
| S3 mass enumeration & download | T1530 | | S3 Data Events |

**Repository:** [enterprise-threat-detection-soc-lab](https://github.com/mahialjaber/enterprise-threat-detection-soc-lab)

---

## 📧 Phishing Triage

Header and payload analysis workflow with automated enrichment — SPF/DKIM/DMARC evaluation, URL and attachment reputation, IOC extraction, analyst verdict.

**Repository:** [CLI-Threat-Analyzer](https://github.com/mahialjaber/CLI-Threat-Analyzer) · *N samples analyzed and documented*

---

## 🧰 Toolchain

| | |
|---|---|
| **SIEM & Detection** | Splunk (SPL) · Sigma · MITRE ATT&CK · Microsoft Sentinel (KQL) |
| **Endpoint & Identity** | Sysmon · Windows Event Logs · Active Directory · PowerShell logging |
| **Cloud** | AWS CloudTrail · IAM · GuardDuty · CloudWatch · S3 · VPC · Lambda |
| **Network** | Wireshark · TCP/IP · DNS · HTTP · packet analysis |
| **Automation** | Python · Bash · Git · REST APIs |
| **Frameworks** | MITRE ATT&CK · NIST SP 800-61 · Cyber Kill Chain |

---

## 📈 Activity

<div align="center">

<img src="https://github-readme-stats.vercel.app/api?username=mahialjaber&show_icons=true&theme=dark&bg_color=0d1117&title_color=1D9E75&icon_color=1D9E75&text_color=c9d1d9&border_color=30363d&hide=stars,issues" height="165"/>
<img src="https://github-readme-streak-stats.herokuapp.com?user=mahialjaber&theme=dark&background=0d1117&ring=1D9E75&fire=1D9E75&currStreakLabel=1D9E75&border=30363d" height="165"/>

<img src="https://github-readme-activity-graph.vercel.app/graph?username=mahialjaber&theme=github-dark&bg_color=0d1117&color=1D9E75&line=1D9E75&point=ffffff&area=true&hide_border=true" width="95%"/>

</div>

---

## 🎯 Currently

- Building out the detection rule library and investigation case files above
- Working toward **Splunk Core Certified Power User**
- Open to entry-level SOC roles and internships — **[get in touch](mailto:mahialjaber.dev@gmail.com)**

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0F6E56,1D9E75,5DCAA5&height=100&section=footer" width="100%"/>

</div>

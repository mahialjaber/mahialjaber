<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0F6E56,1D9E75,5DCAA5&height=190&section=header&text=Mahi%20Al%20Jaber&fontSize=52&fontColor=ffffff&fontAlignY=36&desc=SOC%20Analyst%20%E2%80%94%20Triage%20%C2%B7%20Investigation%20%C2%B7%20Detection%20Engineering&descAlignY=56&descSize=17&animation=fadeIn" width="100%" alt="Mahi Al Jaber — SOC Analyst"/>

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=19&pause=1100&color=1D9E75&center=true&vCenter=true&width=760&lines=Alert+triage+%C2%B7+investigation+%C2%B7+escalation;Sysmon+%C2%B7+Windows+Event+Logs+%C2%B7+Splunk+SPL;Sigma+detections+mapped+to+MITRE+ATT%26CK;Cloud+is+just+another+log+source" alt="Alert triage, investigation, escalation"/>

</div>

<p align="center">
  I work the alerts, and I write the detections that raise them.
</p>

<p align="center">
  <a href="mailto:mahialjaber.dev@gmail.com"><img src="https://img.shields.io/badge/mahialjaber.dev@gmail.com-0D1117?style=flat-square&logo=gmail&logoColor=EA4335" alt="Email"/></a>
  <a href="https://linkedin.com/in/mahialjaber"><img src="https://img.shields.io/badge/in/mahialjaber-0D1117?style=flat-square&logo=linkedin&logoColor=0A66C2" alt="LinkedIn"/></a>
  <img src="https://img.shields.io/badge/Chattogram,%20BD%20·%20UTC+6-0D1117?style=flat-square" alt="Location"/>
</p>

---

Blue team. Most of my hours go where a SOC actually lives: Sysmon and Windows event logs, AD authentication, PowerShell activity, Splunk searches that start as a hunch and end as a rule.

Cloud isn't a separate track for me — it's another log source on the same console. A role session hitting CloudTrail from an address that has no business holding those credentials is the same investigation I'd run on a workstation, with different field names. Being able to follow the attacker across both is the part that stopped me being a beginner.

The loop I enjoy: run the technique in my lab, find it in the logs, write it in Sigma or SPL, then break my own rule until it survives contact with normal traffic. Half of detection engineering turns out to be deleting rules that were never going to fire cleanly. Everything below is the working record of that.

---

## Things I've built

**[enterprise-threat-detection-soc-lab](https://github.com/mahialjaber/enterprise-threat-detection-soc-lab)** — My SOC lab, end to end: endpoint and cloud telemetry ingestion, custom Splunk SPL detections, attack emulation mapped to ATT&CK. The whole pipeline, not a rule in isolation.

**[SOC-Log-Analysis-Datasets](https://github.com/mahialjaber/SOC-Log-Analysis-Datasets)** — Windows, web, firewall, and cloud logs with attack vectors embedded, MIT licensed. Made it because practice data with known ground truth is annoyingly hard to find.

**[CLI-Threat-Analyzer](https://github.com/mahialjaber/CLI-Threat-Analyzer)** — Python terminal tool that parses logs, digests threat-intel reports, and inspects suspicious files. Built to delete the copy-paste half of triage.

**[mitre-attack-study-guide](https://github.com/mahialjaber/mitre-attack-study-guide)** — Offline single-page ATT&CK v19 reference and study tool. Writing it was how I actually learned the matrix.

**[soc-analyst-writeups](https://github.com/mahialjaber/soc-analyst-writeups)** — Investigations from alert to verdict, including the ones I called wrong on the first pass.

*In progress:* a hybrid purple-team SOAR that closes the loop — emulate, detect, respond automatically, measure what the response missed.

---

## In the lab

Techniques I've run end to end: executed the behaviour, pulled the telemetry, wrote the rule, tuned out the noise.

| Technique | ATT&CK | Telemetry | Detection logic |
|---|---|---|---|
| Password spraying against AD | T1110.003 | Windows 4625, 4771 | Failed auth spread wide across accounts from one source, not repeats on one |
| Credential dumping from LSASS | T1003.001 | Sysmon EID 10 | Non-allowlisted process opening `lsass.exe` with read access |
| PowerShell download cradle | T1059.001 | Sysmon, EID 4104 | Encoded commands with Office or script-host parents |
| Service installed for persistence | T1543.003 | Windows 7045 | New service whose binary path sits in a user-writable directory |
| Scheduled task persistence | T1053.005 | Sysmon EID 1, 4698 | Task created by a non-admin identity outside patch windows |
| IAM key created, then used from new infrastructure | T1552.001 | CloudTrail | `CreateAccessKey` → first-seen source ASN for that principal |
| EC2 metadata credential theft | T1552.005 | CloudTrail, VPC Flow | Role session used from an IP that isn't the instance's own |
| CloudTrail logging disabled | T1562.008 | CloudTrail | `StopLogging` / `DeleteTrail` — first event, no threshold |

Last row, roughly as it ships:

```yaml
title: CloudTrail Logging Disabled
status: experimental
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: cloudtrail.amazonaws.com
    eventName:
      - StopLogging
      - DeleteTrail
  condition: selection
level: high
falsepositives:
  - Trail rebuilt by IaC — correlate against the deploy pipeline identity before escalating
```

No threshold on that one. If someone turns off the recorder, the first event is the incident.

---

## Stack

**SIEM & Detection**

![Splunk](https://img.shields.io/badge/Splunk_SPL-0D1117?style=for-the-badge&logo=splunk&logoColor=EA4A2F)
![Sigma](https://img.shields.io/badge/Sigma-0D1117?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-0D1117?style=for-the-badge)
![Sentinel](https://img.shields.io/badge/Sentinel_KQL-0D1117?style=for-the-badge&logo=microsoftazure&logoColor=0078D4)

**Endpoint & Identity**

![Sysmon](https://img.shields.io/badge/Sysmon-0D1117?style=for-the-badge&logo=windows&logoColor=0078D4)
![Windows Event Logs](https://img.shields.io/badge/Windows_Event_Logs-0D1117?style=for-the-badge&logo=windows&logoColor=0078D4)
![Active Directory](https://img.shields.io/badge/Active_Directory-0D1117?style=for-the-badge&logo=microsoft&logoColor=00A4EF)
![PowerShell](https://img.shields.io/badge/PowerShell-0D1117?style=for-the-badge&logo=powershell&logoColor=5391FE)

**Triage & Analysis**

![Alert Triage](https://img.shields.io/badge/Alert_Triage-0D1117?style=for-the-badge)
![Log Analysis](https://img.shields.io/badge/Log_Analysis-0D1117?style=for-the-badge)
![Phishing Analysis](https://img.shields.io/badge/Phishing_Analysis-0D1117?style=for-the-badge)
![Threat Hunting](https://img.shields.io/badge/Threat_Hunting-0D1117?style=for-the-badge)
![IOC Enrichment](https://img.shields.io/badge/IOC_Enrichment-0D1117?style=for-the-badge)

**Network & Traffic**

![Wireshark](https://img.shields.io/badge/Wireshark-0D1117?style=for-the-badge&logo=wireshark&logoColor=1679A7)
![TCP/IP](https://img.shields.io/badge/TCP%2FIP-0D1117?style=for-the-badge)
![DNS](https://img.shields.io/badge/DNS-0D1117?style=for-the-badge)
![PCAP](https://img.shields.io/badge/PCAP_Analysis-0D1117?style=for-the-badge)

**Cloud Telemetry**

![AWS](https://img.shields.io/badge/AWS-0D1117?style=for-the-badge&logo=amazonwebservices&logoColor=FF9900)
![CloudTrail](https://img.shields.io/badge/CloudTrail-0D1117?style=for-the-badge&logo=amazonwebservices&logoColor=FF9900)
![IAM](https://img.shields.io/badge/IAM-0D1117?style=for-the-badge&logo=amazonwebservices&logoColor=FF9900)
![GuardDuty](https://img.shields.io/badge/GuardDuty-0D1117?style=for-the-badge&logo=amazonwebservices&logoColor=FF9900)
![VPC Flow Logs](https://img.shields.io/badge/VPC_Flow_Logs-0D1117?style=for-the-badge&logo=amazonwebservices&logoColor=FF9900)

**Automation & Tooling**

![Python](https://img.shields.io/badge/Python-0D1117?style=for-the-badge&logo=python&logoColor=3776AB)
![Bash](https://img.shields.io/badge/Bash-0D1117?style=for-the-badge&logo=gnubash&logoColor=4EAA25)
![Linux](https://img.shields.io/badge/Linux-0D1117?style=for-the-badge&logo=linux&logoColor=FCC624)
![Kali](https://img.shields.io/badge/Kali-0D1117?style=for-the-badge&logo=kalilinux&logoColor=557C94)
![Docker](https://img.shields.io/badge/Docker-0D1117?style=for-the-badge&logo=docker&logoColor=2496ED)
![Git](https://img.shields.io/badge/Git-0D1117?style=for-the-badge&logo=git&logoColor=F05032)

**Frameworks & Process**

![NIST 800-61](https://img.shields.io/badge/NIST_SP_800--61-0D1117?style=for-the-badge)
![Kill Chain](https://img.shields.io/badge/Cyber_Kill_Chain-0D1117?style=for-the-badge)
![Atomic Red Team](https://img.shields.io/badge/Atomic_Red_Team-0D1117?style=for-the-badge)

---

## How I work an alert

**Scope before anything else.** One host or many, one identity or many. That answers whether this is a ticket or an incident.

**Look for what disproves me.** Writing down the benign explanation first stops me from building a story around the first suspicious field I see.

**Enrich, then escalate.** Identity, owner, change history, reputation. An escalation with no context is a forwarded email.

**Verdict with a confidence level.** "Likely benign, medium confidence, here's what would change my mind" hands off cleanly. "Suspicious" doesn't.

**Every false positive is a tuning ticket.** A rule nobody trusts is worse than no rule.

---

## Now

- Growing the lab's detection library and writing each case up as I close it
- Splunk Core Certified Power User, in progress
- Rebuilding public detection rules in my own environment to find where mine are weaker

---

<p align="center">
  <sub>Open to SOC analyst and detection engineering work — remote or relocating. Happy to walk through any case file in <a href="https://github.com/mahialjaber/soc-analyst-writeups">soc-analyst-writeups</a>.</sub>
</p>

<img src="https://capsule-render.vercel.app/api?type=waving&color=0F6E56,1D9E75,5DCAA5&height=90&section=footer" width="100%" alt=""/>

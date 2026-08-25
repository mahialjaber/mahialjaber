<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0F6E56,1D9E75,5DCAA5&height=190&section=header&text=Mahi%20Al%20Jaber&fontSize=52&fontColor=ffffff&fontAlignY=36&desc=SOC%20Analyst%20%E2%80%94%20Triage%20%C2%B7%20Investigation%20%C2%B7%20Detection%20Engineering&descAlignY=56&descSize=17&animation=fadeIn" width="100%" alt="Mahi Al Jaber — SOC Analyst"/>

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=19&pause=1100&color=1D9E75&center=true&vCenter=true&width=760&lines=Alert+triage+%C2%B7+investigation+%C2%B7+escalation;Sysmon+%C2%B7+Windows+Event+Logs+%C2%B7+Splunk+SPL;Sigma+detections+mapped+to+MITRE+ATT%26CK;Cloud+is+just+another+log+source" alt="Alert triage, investigation, escalation"/>

</div>

<p align="center">
  I work the alerts, and I write the detections that raise them.
</p>

<p align="center">
  <a href="mailto:mahialjaber.dev@gmail.com"><img height="28" src="https://img.shields.io/badge/mahialjaber.dev@gmail.com-C5221F?style=flat-square&logo=gmail&logoColor=white" alt="Email mahialjaber.dev@gmail.com"/></a>
  <a href="https://linkedin.com/in/mahialjaber"><img height="28" src="https://img.shields.io/badge/in%2Fmahialjaber-0A66C2?style=flat-square&logo=linkedin&logoColor=white" alt="LinkedIn in/mahialjaber"/></a>
  <img height="28" src="https://img.shields.io/badge/Chattogram,%20BD%20%C2%B7%20UTC%2B6-44506B?style=flat-square&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBkPSJNMTIgMS41YTcuNiA3LjYgMCAwIDAtNy42IDcuNmMwIDUuNiA3LjYgMTMuNCA3LjYgMTMuNHM3LjYtNy44IDcuNi0xMy40QTcuNiA3LjYgMCAwIDAgMTIgMS41em0wIDQuNGEzLjIgMy4yIDAgMSAxIDAgNi40IDMuMiAzLjIgMCAwIDEgMC02LjR6Ii8%2BPC9zdmc%2B&logoColor=white" alt="Chattogram, Bangladesh - UTC+6"/>
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

<!--
  Stack badges. One fill colour per category, all >=4.5:1 with white text and
  visible against both GitHub themes (never use 0D1117 - it is the exact dark
  background colour, so the pill vanishes).

  Icons: `logo=<slug>` uses Simple Icons. Note that Microsoft, Amazon and
  Google icons were withdrawn from that set, so those slugs render nothing.
  Every other icon here is a hand-drawn SVG embedded as
  `logo=data:image/svg%2Bxml;base64,...` - self-contained, nothing to break.

  To add a badge, copy a neighbour and change the label; underscore = space,
  `--` = a literal hyphen, and %26 / %2F escape & and /.
-->

**SIEM &amp; Detection**

<p>
  <img height="34" src="https://img.shields.io/badge/Splunk_SPL-0F6E56?style=for-the-badge&logo=splunk&logoColor=white" alt="Splunk SPL"/>
  <img height="34" src="https://img.shields.io/badge/Sigma-0F6E56?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZD0iTTE4LjYgMy40SDZsNyA4LjYtNyA4LjZoMTIuNiIgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjZmZmIiBzdHJva2Utd2lkdGg9IjIuNiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8%2BPC9zdmc%2B&logoColor=white" alt="Sigma"/>
  <img height="34" src="https://img.shields.io/badge/MITRE_ATT%26CK-0F6E56?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZD0iTTIuNiAyLjZoNS40VjhIMi42em02LjcgMGg1LjRWOEg5LjN6bTYuNyAwaDUuNFY4SDE2ek0yLjYgOS4zaDUuNHY1LjRIMi42em02LjcgMGg1LjR2NS40SDkuM3ptNi43IDBoNS40djUuNEgxNnpNMi42IDE2aDUuNHY1LjRIMi42em02LjcgMGg1LjR2NS40SDkuM3ptNi43IDBoNS40djUuNEgxNnoiLz48L3N2Zz4%3D&logoColor=white" alt="MITRE ATT&amp;CK"/>
  <img height="34" src="https://img.shields.io/badge/Sentinel_KQL-0F6E56?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBkPSJNMTIgMS43IDMuNCA0Ljh2Ni41YzAgNS4zIDMuNyA5LjggOC42IDExLjEgNC45LTEuMyA4LjYtNS44IDguNi0xMS4xVjQuOHptMCA2LjFjMyAwIDUuMiAyLjIgNi4xIDQuMS0uOSAxLjktMy4xIDQuMS02LjEgNC4xcy01LjItMi4yLTYuMS00LjFjLjktMS45IDMuMS00LjEgNi4xLTQuMXptMCAxLjlhMi4yIDIuMiAwIDEgMCAwIDQuNCAyLjIgMi4yIDAgMCAwIDAtNC40eiIvPjwvc3ZnPg%3D%3D&logoColor=white" alt="Sentinel KQL"/>
</p>

**Endpoint &amp; Identity**

<p>
  <img height="34" src="https://img.shields.io/badge/Sysmon-1F5FA8?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBkPSJNMS40IDMuMmgyMS4ydjEzLjRIMS40em0yLjMgMi4zdjguOGgxNi42VjUuNXoiLz48cGF0aCBkPSJNOC43IDE4LjFoNi42djIuNEg4Ljd6Ii8%2BPGNpcmNsZSBjeD0iMTIiIGN5PSI5LjkiIHI9IjIuNSIvPjwvc3ZnPg%3D%3D&logoColor=white" alt="Sysmon"/>
  <img height="34" src="https://img.shields.io/badge/Windows_Event_Logs-1F5FA8?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZD0iTTIuNCAzLjJoOC4zdjguM0gyLjR6bTEwLjkgMGg4LjN2OC4zaC04LjN6TTIuNCAxMy40aDguM3Y4LjNIMi40em0xMC45IDBoOC4zdjguM2gtOC4zeiIvPjwvc3ZnPg%3D%3D&logoColor=white" alt="Windows Event Logs"/>
  <img height="34" src="https://img.shields.io/badge/Active_Directory-1F5FA8?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZD0iTTkuMiAxLjhoNS42djQuOEg5LjJ6Ii8%2BPHBhdGggZD0iTTExLjMgNi42aDEuNHY0LjNoLTEuNHoiLz48cGF0aCBkPSJNNC4xIDEwLjloMTUuOHYxLjRINC4xeiIvPjxwYXRoIGQ9Ik00LjEgMTEuNmgxLjR2My40SDQuMXptNy4yIDBoMS40djMuNGgtMS40em03LjIgMGgxLjR2My40aC0xLjR6Ii8%2BPHBhdGggZD0iTTEuOCAxNWg1LjZ2NC44SDEuOHptNy40IDBoNS42djQuOEg5LjJ6bTcuNCAwaDUuNnY0LjhoLTUuNnoiLz48L3N2Zz4%3D&logoColor=white" alt="Active Directory"/>
  <img height="34" src="https://img.shields.io/badge/PowerShell-1F5FA8?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBkPSJNMS40IDMuMmgyMS4ydjE3LjZIMS40em0yLjMgMi4zdjEzaDE2LjZ2LTEzeiIvPjxwYXRoIGQ9Ik01LjYgOC4xIDEwIDExLjhsLTQuNCAzLjd6Ii8%2BPHBhdGggZD0iTTExLjIgMTMuNmg2LjZ2MS45aC02LjZ6Ii8%2BPC9zdmc%2B&logoColor=white" alt="PowerShell"/>
</p>

**Triage &amp; Analysis**

<p>
  <img height="34" src="https://img.shields.io/badge/Alert_Triage-6D4AA6?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBkPSJNMTIgMiAxLjMgMjAuOGgyMS40em0tMS4xIDYuMmgyLjJ2Ni4zaC0yLjJ6bTAgNy45aDIuMnYyLjNoLTIuMnoiLz48L3N2Zz4%3D&logoColor=white" alt="Alert Triage"/>
  <img height="34" src="https://img.shields.io/badge/Log_Analysis-6D4AA6?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBkPSJNMy45IDEuN2gxMC44bDUuNCA1LjR2MTUuMkgzLjl6bTIuMyAyLjN2MTZoMTEuNVY4LjNoLTQuNFY0em0xLjkgNS4xaDQuNnYxLjlIOC4xem0wIDRoOC40djEuOUg4LjF6bTAgNGg4LjR2MS45SDguMXoiLz48L3N2Zz4%3D&logoColor=white" alt="Log Analysis"/>
  <img height="34" src="https://img.shields.io/badge/Phishing_Analysis-6D4AA6?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBkPSJNMS40IDQuM2gyMS4ydjE1LjRIMS40em0yLjMgMi4zdjEwLjhoMTYuNlY2LjZ6Ii8%2BPHBhdGggZD0ibTQuNCA2LjcgNy42IDUuNCA3LjYtNS40IDEuMyAxLjktOC45IDYuMy04LjktNi4zeiIvPjwvc3ZnPg%3D%3D&logoColor=white" alt="Phishing Analysis"/>
  <img height="34" src="https://img.shields.io/badge/Threat_Hunting-6D4AA6?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBkPSJNMTIgMS40YTEwLjYgMTAuNiAwIDEgMCAwIDIxLjIgMTAuNiAxMC42IDAgMCAwIDAtMjEuMnptMCAyLjRhOC4yIDguMiAwIDEgMSAwIDE2LjQgOC4yIDguMiAwIDAgMSAwLTE2LjR6Ii8%2BPHBhdGggZD0iTTEwLjkgMGgyLjJ2Ni4yaC0yLjJ6bTAgMTcuOGgyLjJWMjRoLTIuMnpNMCAxMC45aDYuMnYyLjJIMHptMTcuOCAwSDI0djIuMmgtNi4yeiIvPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTIiIHI9IjIuNiIvPjwvc3ZnPg%3D%3D&logoColor=white" alt="Threat Hunting"/>
  <img height="34" src="https://img.shields.io/badge/IOC_Enrichment-6D4AA6?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBkPSJNOS45IDEuNmE4LjMgOC4zIDAgMSAwIDUgMTQuOWw0LjkgNC45IDEuOS0xLjktNC45LTQuOUE4LjMgOC4zIDAgMCAwIDkuOSAxLjZ6bTAgMi40YTUuOSA1LjkgMCAxIDEgMCAxMS44IDUuOSA1LjkgMCAwIDEgMC0xMS44eiIvPjxwYXRoIGQ9Ik04LjkgNi4xaDJ2Ny42aC0yeiIvPjxwYXRoIGQ9Ik02LjEgOC45aDcuNnYySDYuMXoiLz48L3N2Zz4%3D&logoColor=white" alt="IOC Enrichment"/>
</p>

**Network &amp; Traffic**

<p>
  <img height="34" src="https://img.shields.io/badge/Wireshark-116E7C?style=for-the-badge&logo=wireshark&logoColor=white" alt="Wireshark"/>
  <img height="34" src="https://img.shields.io/badge/TCP%2FIP-116E7C?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZD0iTTIuNCA1LjloMTMuM2wtMy40LTMuNEwxNCAuOWw2IDYtNiA2LTEuNy0xLjYgMy40LTMuNEgyLjR6Ii8%2BPHBhdGggZD0iTTIxLjYgMTguMUg4LjNsMy40IDMuNC0xLjcgMS42LTYtNiA2LTYgMS43IDEuNi0zLjQgMy40aDEzLjN6Ii8%2BPC9zdmc%2B&logoColor=white" alt="TCP/IP"/>
  <img height="34" src="https://img.shields.io/badge/DNS-116E7C?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBkPSJNMTIgMS40YTEwLjYgMTAuNiAwIDEgMCAwIDIxLjIgMTAuNiAxMC42IDAgMCAwIDAtMjEuMnptMCAyLjJhOC40IDguNCAwIDEgMSAwIDE2LjggOC40IDguNCAwIDAgMSAwLTE2Ljh6Ii8%2BPHBhdGggZD0iTTIuNCAxMC45aDE5LjJ2Mi4ySDIuNHoiLz48cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xMiAxLjRjLTIuOSAwLTUuMyA0LjctNS4zIDEwLjZTOS4xIDIyLjYgMTIgMjIuNnM1LjMtNC43IDUuMy0xMC42UzE0LjkgMS40IDEyIDEuNHptMCAyLjJjMS40IDAgMy4xIDMuNiAzLjEgOC40cy0xLjcgOC40LTMuMSA4LjQtMy4xLTMuNi0zLjEtOC40UzEwLjYgMy42IDEyIDMuNnoiLz48L3N2Zz4%3D&logoColor=white" alt="DNS"/>
  <img height="34" src="https://img.shields.io/badge/PCAP_Analysis-116E7C?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZD0iTTEuOCAxMy45aDIuOHY2LjdIMS44em00LjctNC44aDIuOHYxMS41SDYuNXptNC43LTUuOWgyLjh2MTcuNGgtMi44em00LjcgMy45aDIuOHYxMy41aC0yLjh6bTQuNyA0LjloMi44djguNmgtMi44eiIvPjwvc3ZnPg%3D%3D&logoColor=white" alt="PCAP Analysis"/>
</p>

**Cloud Telemetry**

<p>
  <img height="34" src="https://img.shields.io/badge/AWS-A85B10?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZD0iTTE4LjQgMTkuNkg2LjdBNS40IDUuNCAwIDAgMSA2LjEgOC44YTcuMSA3LjEgMCAwIDEgMTMuNCAxLjcgNC42IDQuNiAwIDAgMS0xLjEgOS4xeiIvPjwvc3ZnPg%3D%3D&logoColor=white" alt="AWS"/>
  <img height="34" src="https://img.shields.io/badge/CloudTrail-A85B10?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZD0iTTE3LjQgMTIuOUg2LjZBNC43IDQuNyAwIDAgMSA2LjEgMy42YTYuMiA2LjIgMCAwIDEgMTEuNyAxLjUgNCA0IDAgMCAxLS40IDcuOHoiLz48Y2lyY2xlIGN4PSI1LjYiIGN5PSIxOC42IiByPSIyIi8%2BPGNpcmNsZSBjeD0iMTIiIGN5PSIxOC42IiByPSIyIi8%2BPGNpcmNsZSBjeD0iMTguNCIgY3k9IjE4LjYiIHI9IjIiLz48L3N2Zz4%3D&logoColor=white" alt="CloudTrail"/>
  <img height="34" src="https://img.shields.io/badge/IAM-A85B10?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBkPSJNMTUuNiAxLjdhNi43IDYuNyAwIDAgMC02LjQgOC43TDEuNiAxOHY0LjNoNC4zbDEuNC0xLjR2LTIuNGgyLjRsMS42LTEuN3YtMi4ybDIuMy0yLjNhNi43IDYuNyAwIDEgMCAyLTEwLjZ6bTEuNiAzLjFhMiAyIDAgMSAxIDAgNCAyIDIgMCAwIDEgMC00eiIvPjwvc3ZnPg%3D%3D&logoColor=white" alt="IAM"/>
  <img height="34" src="https://img.shields.io/badge/GuardDuty-A85B10?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBkPSJNMTIgMS43IDMuNCA0Ljh2Ni41YzAgNS4zIDMuNyA5LjggOC42IDExLjEgNC45LTEuMyA4LjYtNS44IDguNi0xMS4xVjQuOHptNC41IDYuNiAxLjcgMS43LTYuNyA2LjctMy45LTMuOSAxLjctMS43IDIuMiAyLjJ6Ii8%2BPC9zdmc%2B&logoColor=white" alt="GuardDuty"/>
  <img height="34" src="https://img.shields.io/badge/VPC_Flow_Logs-A85B10?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPGNpcmNsZSBjeD0iNC40IiBjeT0iNC44IiByPSIzIi8%2BPGNpcmNsZSBjeD0iMTkuNiIgY3k9IjQuOCIgcj0iMyIvPjxjaXJjbGUgY3g9IjEyIiBjeT0iMTkuMiIgcj0iMyIvPjxwYXRoIGQ9Im02LjQgNi41IDQuMyA5LjktMS44LjhMNC42IDcuM3ptMTEuMiAwIDEuOC44LTQuMyA5LjktMS44LS44eiIvPjxwYXRoIGQ9Ik03LjQgMy44aDkuMnYySDcuNHoiLz48L3N2Zz4%3D&logoColor=white" alt="VPC Flow Logs"/>
</p>

**Automation &amp; Tooling**

<p>
  <img height="34" src="https://img.shields.io/badge/Python-44506B?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img height="34" src="https://img.shields.io/badge/Bash-44506B?style=for-the-badge&logo=gnubash&logoColor=white" alt="Bash"/>
  <img height="34" src="https://img.shields.io/badge/Linux-44506B?style=for-the-badge&logo=linux&logoColor=white" alt="Linux"/>
  <img height="34" src="https://img.shields.io/badge/Kali-44506B?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali"/>
  <img height="34" src="https://img.shields.io/badge/Docker-44506B?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"/>
  <img height="34" src="https://img.shields.io/badge/Git-44506B?style=for-the-badge&logo=git&logoColor=white" alt="Git"/>
</p>

**Frameworks &amp; Process**

<p>
  <img height="34" src="https://img.shields.io/badge/NIST_SP_800--61-8C2F52?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBkPSJNOC42IDEuNGg2Ljh2Mi4yaDQuMnYxOUg0LjR2LTE5aDQuMnpNNi43IDUuOXYxNC40aDEwLjZWNS45aC0xLjl2MS45SDguNlY1Ljl6bTIuMiA1LjJoNi4yVjEzSDguOXptLTEuNiA0LjRoNy44djEuOUg3LjN6Ii8%2BPC9zdmc%2B&logoColor=white" alt="NIST SP 800-61"/>
  <img height="34" src="https://img.shields.io/badge/Cyber_Kill_Chain-8C2F52?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPGcgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjZmZmIiBzdHJva2Utd2lkdGg9IjIuNyI%2BPGNpcmNsZSBjeD0iOC42IiBjeT0iMTIiIHI9IjUuNCIvPjxjaXJjbGUgY3g9IjE1LjQiIGN5PSIxMiIgcj0iNS40Ii8%2BPC9nPjwvc3ZnPg%3D%3D&logoColor=white" alt="Cyber Kill Chain"/>
  <img height="34" src="https://img.shields.io/badge/Atomic_Red_Team-8C2F52?style=for-the-badge&logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iI2ZmZiI%2BPGcgZmlsbD0ibm9uZSIgc3Ryb2tlPSIjZmZmIiBzdHJva2Utd2lkdGg9IjIuNCI%2BPGVsbGlwc2UgY3g9IjEyIiBjeT0iMTIiIHJ4PSIxMC40IiByeT0iNC4zIiB0cmFuc2Zvcm09InJvdGF0ZSgzNSAxMiAxMikiLz48ZWxsaXBzZSBjeD0iMTIiIGN5PSIxMiIgcng9IjEwLjQiIHJ5PSI0LjMiIHRyYW5zZm9ybT0icm90YXRlKC0zNSAxMiAxMikiLz48L2c%2BPGNpcmNsZSBjeD0iMTIiIGN5PSIxMiIgcj0iMy4zIi8%2BPC9zdmc%2B&logoColor=white" alt="Atomic Red Team"/>
</p>

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

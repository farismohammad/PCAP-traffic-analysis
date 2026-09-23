# PCAP Traffic Analysis

Practical network traffic investigations using public PCAP datasets, with documented analysis and incident findings.

These are training investigations based on public exercises from [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/), not reports from client environments.

## Investigations

| Report | Focus |
| --- | --- |
| [BurninCandle](IncidentReport_BurninCandle.md) | Host identification, suspicious connections, beaconing observations, and IcedID-related indicators |
| [SunnyStation](IncidentReport_SunnyStation.md) | Investigation of multiple workstations, HTTP/HTTPS and SMTP activity, extracted-file analysis, and Emotet/Formbook findings |

## Reading the reports

Each report connects an executive summary with technical observations and indicators of compromise. Start with the summary, then follow the host, traffic, and file evidence through the technical sections. Findings and threat-intelligence references reflect the time of the original exercises; indicators are historical, not a current blocklist.

## Reproduce the analysis

1. Open the original exercise linked at the top of each report to obtain its PCAP and scenario.
2. Inspect the capture with a packet-analysis tool such as Wireshark, correlating hosts, timestamps, protocols, and destinations.
3. Compare your observations with the report and the original exercise material.

The SunnyStation report also describes FLOSS, CyberChef, and threat-intelligence lookups used during analysis. Reading the Markdown reports requires no installation. Treat exercise captures and extracted artifacts as potentially malicious and use an isolated analysis environment.

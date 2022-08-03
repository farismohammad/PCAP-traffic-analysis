# BurninCandle Exercise 
Link to exercise and pcap files `https://www.malware-traffic-analysis.net/2022/03/21/index3.html`

# Incident Report

### Executive Summary

Patrick Zimmerman's machine was infected with an IcedID aka BokBot. IcedID is a banking trojan that targets a user's financial information leading to bank account compromise and fraudulent transactions being conducted. It is also capable of acting as a dropper for other malware. It could have been used as a secondary payload from other malware or sent in a malicious email.

### Technical Details 
>User : `patrick.zimmerman`
OS : `Windows` <br>
Name : `DESKTOP-5QS3D5D` <br>
MAC address : `00:60:52:b7:33:0f` <br>
IP `10.0.19.14`<br>

A file was downloaded from a file sharing website `situla.bitbit.net 87.238.33.8`. It also connected with another legitimate file sharing service `filebin.net 185.47.40.36`<br>
Beaconing behavior was observed to `bupdater.com 23.227.198.203` HTTPS traffic over `port 757`. The host machine initiated a TCP connection to the domain every minute but never completed the TCP handshake (SYN-SYN_ACK).

Other suspicious domains the host connected to are: <br>
>`oceriesfornot[.]top 188.166.154.118 HTTP 80` <br>
`antnosience[.]com 157.245.142.66 HTTPS 443` <br>
`suncoastpinball[.]com 160.153.32.99 HTTPS 443` <br>
`seaskysafe[.]com 91.193.16.181 HTTPS 443` <br>

These IPs are flagged as malicious on virus total and was also seen by cybereason and attributed to be a IcedID C2. <br> Reference : `https://www.cybereason.com/blog/cybereason-vs.-quantum-locker-ransomware`

### Indicators Of Compromise (IOCs):


>situla.bitbit[.]net 87.238.33.8 <br>
filebin[.]net 185.47.40.36<br>
bupdater[.]com 23.227.198.203<br>
oceriesfornot[.]top 188.166.154.118<br>
antnosience[.]com 157.245.142.66<br>
suncoastpinball[.]com 160.153.32.99<br>
seaskysafe[.]com 91.193.16.181<br>

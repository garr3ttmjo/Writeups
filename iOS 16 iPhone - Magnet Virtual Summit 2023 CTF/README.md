# Magnet Virtual Summit 2023 CTF - iOS 16 iPhone

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

Scroll through the photos and there is a grouping that seems to be from an outlook looking over the city with maybe a stadium in the background.

For example private/var/mobile/Media/DCIM/100APPLE/IMG_0032.HEIC.

<img width="697" alt="image" src="https://github.com/user-attachments/assets/c5710860-9f52-4031-8b50-eb3d5ed2792a">

Extract the metadata with exiftool and then use the coordinates to get the locations. It laces him in Mount Royal Park right outside Belvédère Camillien-Houde. To the east of this location we can see the Percival Molson Memorial Stadium is within eye distance.

<img width="878" alt="image" src="https://github.com/user-attachments/assets/10d97596-066d-44a1-ae33-ac9b50147ec0">

#### 9. What light-hearted game did the user spend the most time on?
Application usage is not something iLEAPP parses either so back to manual.

Cellebrite is an industry expert on mobile forensics and here is an article they put out talking about app usage from screen time tracking.

https://cellebrite.com/en/a-look-into-apples-screen-time-feature-and-what-insights-it-lends-to-digital-intelligence/

We can query the RMAdminStore-Local.sqlite db found at private/var/mobile/Library/Application Support/com.apple.remotemanagementd. 

The table contains the data we are looking for so we can do something like

```
select distinct ZBUNDLEIDENTIFIER, ZTOTALTIMEINSECONDS from ZUSAGETIMEDITEM order by ZTOTALTIMEINSECONDS desc;

ZBUNDLEIDENTIFIER|ZTOTALTIMEINSECONDS
com.apple.Maps|3600
com.apple.Maps|875
com.apple.AppStore|849
com.apple.AppStore|762
com.hammerandchisel.discord|707
com.midasplayer.apps.candycrushsaga|577
com.google.ios.youtube|562
com.apple.weather|513
com.apple.Maps|454
com.google.photos|424
com.apple.camera|423
com.yikyak.2|399
com.apple.camera|385
com.reddit.Reddit|368
com.google.chrome.ios|354
com.google.Gmail|353
com.google.chrome.ios|353
```
If we go down the list we see the 6th highest application is candy crush at around 10 minutes of usage. You can also look in the Biome AppInFocus report from iLEAPP and search "candy crush" to find it was in focus between 2022-12-23 16:43:19 and 2022-12-23 16:52:56, for about 8 minutes.

#### 10. Which airline lounge was viewed?

The only reference to a lounge I could find was in the Biome User Activity Metadata report from an Apple Maps search for "Lufthansa Senator Lounge in Newark".

<img width="1346" alt="image" src="https://github.com/user-attachments/assets/f2a587e6-80fb-437a-96a1-8b2030b0fed9">

#### 11. Which terms and conditions site on Tik Tok is named after a space formation?

At first I looked in the TikTok app location at private/var/containers/Bundle/Application/DADABF7F-CAA3-4724-8CA4-A1C0434774E8/TikTok.app but after a lot of searching found no results. One thing I thought was weird was that there were no sqlite db for storing any settings or data. I did some research and found there was another locations but associated with bytedance the parent company. The GUID parser I was using had this under musically so I missed it but the location is /private/var/mobile/Containers/Data/Application/4F9E5274-DDB7-422E-8629-234C84D24F4E. 

I run the below command in the directory trying to find an database related to terms and conditions.

```
find . -type f -name "*.sqlite" -exec grep -H "terms" {} \;        
Binary file ./Library/AWEStorage/UnifyStorage.sqlite matches
```
Then I focus on this UnifyStorage.sqlite file. I use strings and look for mention of the words terms, conditions, and then finally legal and I get a match.
```
strings Library/AWEStorage/UnifyStorage.sqlite | grep legal | less

Ghttps://www.tiktok.com/falcon/forest/nebula/common_legal?hide_nav_bar=1_
4https://www.tiktok.com/falcon/forest/nebula/ad_legal
```

This url has a nebula directory which is the mentioned space formation.

#### 12. Which cardinal direction was the user turning when driving towards RHEINFAHRE?

Doing an Apple Maps search for RHEINFARHE shows it is a location in Germany.

Location
-------------
Rheinfähre
67583 Guntersblum
Rhineland-Palatinate
Germany
Coordinates
-------------
49.80799° N, 8.39196° E

I wrote a python script to extract geolocation data from artifacts like photos and the ZRTCLLOCATIONMO so I could have them mapped out for better visualization. The Rhine River is in Germany so we can narrow it down to the photos in Germany.

<img width="1179" alt="image" src="https://github.com/user-attachments/assets/a4678e30-adff-493e-8670-a6d2caa81f65">

Going through the images there is one photo with a sign directing towards RHEINFARHE or Rhine Ferry.

<img width="671" alt="image" src="https://github.com/user-attachments/assets/a0204847-f46b-4e40-8496-274eee9336e0">

Putting the coordinates from the picture in maps shows they are likely heading down WEINHEIMER STRABE towards Oestrich-Winkel and the river. This would make their direction South with maybe a little East.

<img width="372" alt="image" src="https://github.com/user-attachments/assets/2f57b0fb-1748-4a47-9394-9b2b90c53fbd">

#### 13. The user was trying to learn German through an application, what promotion featuring a rocket was most commonly shown to the user?

Searching through the applications I find that Duolingo is installed. So to search for Duolingo related files
```
find . -iname "*duolingo*"
```
Promotion makes me think of advertisment or comerical and in the output of this search I see some .mp4 files so I am going to filter for those.

```
find . -iname "*duolingo*" | grep .mp4

./private/var/mobile/Containers/Data/Application/89A6AE48-C46D-4405-A187-C7FF439873F3/Documents/plus-ad-video/Duolingo_NYPromo_2023_EN.mp4
./private/var/mobile/Containers/Data/Application/89A6AE48-C46D-4405-A187-C7FF439873F3/Documents/plus-ad-video/Duolingo_FamilyPlan_Super_EN_2.mp4
./private/var/mobile/Containers/Data/Application/89A6AE48-C46D-4405-A187-C7FF439873F3/Documents/plus-ad-video/Duolingo_NYPromo_2023_VO_EN.mp4
```
Open the first .mp4 file for the NYPromo and it is the Duolingo bird on a rocket and its a promo for Super Duolingo for the New Year.

<img width="484" alt="image" src="https://github.com/user-attachments/assets/6d332227-a65d-4281-826d-b49d78391693">

#### 14. At which location did the user travel the most meters according to Apple? (City, Country)

This is a good article on health activity tracked through Apple Watch https://dfir.pubpub.org/pub/xqvcn3hj/release/1#:~:text=Once%20a%20file%20system%20extraction,sqlite%2C%20healthdb_secure

Distance data can be found in the one of the health related database private/var/mobile/Library/Health/healthdb_secure.sqlite.

Combining the quantity_samples and samples tables, some datetime manipulation to adjust for America/New_York timezone, and then filtering for a sample.data_id = 8 for "Distance Traveled" we can get an accurate picture of the greatest distance in meters traveled by our user. The top record is 662 meters on 2022-12-31.

```
SELECT 
    samples.data_id, 
    quantity_samples.quantity, 
    datetime(samples.start_date + 978307200 - 18000, 'unixepoch', 'utc') AS "StartTime", 
    datetime(samples.end_date + 978307200 - 18000, 'unixepoch', 'utc') AS "EndTime" 
FROM 
    quantity_samples 
INNER JOIN 
    samples 
ON 
    samples.data_id = quantity_samples.data_id 
WHERE 
    samples.data_type = 8 
ORDER BY 
    quantity DESC 
LIMIT 
    5;

data_id|quantity|StartTime|EndTime
1392|662.19000000001|2022-12-31 14:35:18|2022-12-31 14:45:07
1076|648.190000000005|2022-12-27 13:27:57|2022-12-27 13:37:48
968|599.979999999997|2022-12-24 08:03:08|2022-12-24 08:13:07
1398|584.890000000018|2022-12-31 14:45:25|2022-12-31 14:55:24
1249|576.939999999991|2022-12-29 14:34:28|2022-12-29 14:44:27
```
Now we can check the dates of the photos taken to see if any were taken during this timeframe (2022-12-31 14:35:18|2022-12-31 14:45:07) that could provide the geo location data.

We have a match with 

```
exiftool IMG_0066.HEIC

Create Date                     : 2022:12:31 14:40:47.660+01:00
Date/Time Original              : 2022:12:31 14:40:47.660+01:00
Modify Date                     : 2022:12:31 14:40:47+01:00
GPS Altitude                    : 94.7 m Above Sea Level
GPS Latitude                    : 50 deg 1' 14.05" N
GPS Longitude                   : 8 deg 5' 37.87" E
Circle Of Confusion             : 0.005 mm
Field Of View                   : 69.4 deg
Focal Length                    : 4.2 mm (35 mm equivalent: 26.0 mm)
GPS Position                    : 50 deg 1' 14.05" N, 8 deg 5' 37.87" E
Hyperfocal Distance             : 2.27 m
Light Value                     : 12.8
Lens ID                         : iPhone 12 back dual wide camera 4.2mm f/1.6
```

Coordinates: 50.02057, 8.09385

The answer is Eltville am Rhein, Germany.

#### 15. What weather front was warned to the user by youtube?

The Biome Notifications Public report parsed by ILEAPP provided a notification from YouTube related to an artic front in Spanish on 2022-12-21.

<img width="548" alt="image" src="https://github.com/user-attachments/assets/09497635-1285-4a03-ab9b-b7bb0c7f3272">





















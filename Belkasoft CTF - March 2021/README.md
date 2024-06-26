# Belkasoft CTF - March 2021

**Date:** June 25th, 2024

**Author:** Garrett Jones

Challenge created by Belkasoft and can be found at:
 * https://belkasoft.com/ctf_march/

**Concepts:** Sleuthkit (TSK), Windows Disk Forensics

## Scenario
You were contacted by a company preparing their new product launch: an AI-based recommendation system that respects target privacy. Just before the date, the source code and technical documents ended up in their competitor's hands. The company suspects a recently hired developer and obtained a copy of his corporate laptop HDD. You are going to analyze the image and support the suspicion with evidence extracted from the laptop...

## Note
I am obviously a little late to this challenge but it has been a good learning experience and I have challenged myself to use the Sleuthkit (TSK) framework from the command line as my main analysis tool.

## Investigation
We are provided SUSPECT.E01 for the disk image to investigate. I am going to convert it to a raw format because I had some issues parsing the E01 format which ends up with a 43 GB SUSPECT.raw image.

For those unfamiliar with The Sleuthkit it was developed by Brian Carrier and is a is a collection of command line tools and a C library that allows you to analyze disk images and recover files from them. It is used behind the scenes in Autopsy and many other open source and commercial forensics tools.
I will be working from my Mac so I use the Homebrew package manager to install it with the command "brew install sleuthkit"

To start off I am going to use the mmls command to take a look at the partion structure of the disk image.

```
mmls - display the partition layout of a volume system  (partition tables)

--------------------------------------------------------------------------------------

mmls SUSPECT.raw 
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0001126399   0001124352   NTFS / exFAT (0x07)
003:  000:001   0001126400   0083884031   0082757632   NTFS / exFAT (0x07)
004:  -------   0083884032   0083886079   0000002048   Unallocated
```

Looking at the output there are two NTFS partitions to look at to determine the main volume. To look into further each partion I will use the fls command. To view each partition provide the starting sector offset for each partition.

```
fls - List file and directory names in a disk image.

--------------------------------------------------------------------------------------

fls -o 2048 SUSPECT.raw 
r/r 4-128-1:	$AttrDef
r/r 8-128-2:	$BadClus
r/r 8-128-1:	$BadClus:$Bad
r/r 6-128-4:	$Bitmap
r/r 7-128-1:	$Boot
d/d 11-144-4:	$Extend
r/r 2-128-1:	$LogFile
r/r 0-128-6:	$MFT
r/r 1-128-1:	$MFTMirr
d/d 179-144-1:	$RECYCLE.BIN
r/r 9-128-8:	$Secure:$SDS
r/r 9-144-11:	$Secure:$SDH
r/r 9-144-14:	$Secure:$SII
r/r 10-128-1:	$UpCase
r/r 10-128-4:	$UpCase:$Info
r/r 3-128-3:	$Volume
d/d 36-144-5:	Boot
r/r 139-128-1:	bootmgr
r/r 161-128-1:	BOOTNXT
r/r 165-128-3:	BOOTSECT.BAK
d/d 168-144-1:	Recovery
d/d 166-144-1:	System Volume Information
V/V 256:	$OrphanFiles

--------------------------------------------------------------------------------------

fls -o 1126400 SUSPECT.raw
d/d 80328-144-1:	Documents and Settings
d/d 237-144-6:	ProgramData
d/d 396-144-5:	Users
r/r 4-128-1:	$AttrDef
r/r 8-128-2:	$BadClus
r/r 8-128-1:	$BadClus:$Bad
r/r 6-128-4:	$Bitmap
r/r 7-128-1:	$Boot
d/d 11-144-4:	$Extend
r/r 2-128-1:	$LogFile
r/r 0-128-6:	$MFT
r/r 1-128-1:	$MFTMirr
d/d 58-144-5:	$Recycle.Bin
r/r 9-128-8:	$Secure:$SDS
r/r 9-144-16:	$Secure:$SDH
r/r 9-144-18:	$Secure:$SII
r/r 10-128-1:	$UpCase
r/r 10-128-4:	$UpCase:$Info
r/r 3-128-3:	$Volume
r/r 21575-128-1:	autoexec.bat
r/r 21577-128-1:	config.sys
d/d 59-144-1:	PerfLogs
d/d 61-144-6:	Program Files
d/d 80574-144-1:	Recovery
r/r 79302-128-1:	swapfile.sys
d/d 79295-144-6:	System Volume Information
d/d 101788-144-1:	tools
d/d 453-144-5:	Windows
V/V 177408:	$OrphanFiles
r/r 50-128-1:	hiberfil.sys
r/r 79301-128-1:	pagefile.sys
```
Viewing the file contents of each partition shows the second one with a starting sector offset of 1126400 is the main volume we will want to be looking at containing user information.

To navigate through the file system you take can use the icat command to output the contents of the file or you can use the fls command to navigate through the directories. To do this you need to provide the inode to the end of the command. This can be found in the second column of the fls output.

## Sleuthkit Examples:
```
Reading contents of autoexec.bat
----------------------------------------
icat -o 1126400 SUSPECT.raw 21575-128-1
REM Dummy file for NTVDM%
```
```
Extracting $MFT for further analysis
----------------------------------------
icat -o 1126400 SUSPECT.raw 0-128-6 > MFT.raw
```
```
Checking file type by piping into file command
----------------------------------------
icat -o 1126400 SUSPECT.raw 21575-128-1 | file -
/dev/stdin: ASCII text, with no line terminators
```
```
Viewing contents of Users directory
----------------------------------------
fls -o 1126400 SUSPECT.raw 396-144-5     
d/d 83879-144-6:	Administrator
d/d 22240-144-1:	All Users
d/d 83898-144-6:	anit.ghosh
d/d 397-144-5:	Default
d/d 22241-144-1:	Default User
r/r 22243-128-1:	desktop.ini
d/d 445-144-5:	Public
d/d 81171-144-5:	User
```
```
Recursivly viewing contents of $Recycle.Bin directory
----------------------------------------
fls -r -o 1126400 SUSPECT.raw 58-144-5
d/d 81885-144-1:	S-1-5-18
+ r/r 81886-128-1:	desktop.ini
d/d 84670-144-1:	S-1-5-21-3064058907-2826536974-2889819764-1106
+ r/r 84671-128-1:	desktop.ini
d/d 85947-144-1:	S-1-5-21-3064058907-2826536974-2889819764-500
+ r/r 85948-128-1:	desktop.ini
d/d 81091-144-1:	S-1-5-21-672274782-2342008316-3472871522-1000
+ r/r 81092-128-1:	desktop.ini
d/d 81805-144-1:	S-1-5-21-672274782-2342008316-3472871522-1001
+ r/r 81806-128-1:	desktop.ini
d/d 79320-144-1:	S-1-5-21-846388080-3680834429-2020154290-1001
+ r/r 80352-128-1:	desktop.ini
```
## Timelime and MFT
Other setup I am going to do before I start looking into the questions is to create a timeline using Sleuthkit and also parse the MFT using the nfts_dfir python tool.

### Timeline
Setting up a timeline can provided valuable high level insight into a users activity as you can see what files were last created, modified, etc.T he issue is there is a lot of data so you need to find ways to narrow it down.
```
This command recursivly lists everything in a volume and produces a body file with the MACB times for each file so it can read by the mactime tool.

  fls -r -o 1126400 -m / SUSPECT.raw > SUSPECT_body.txt
  
  head SUSPECT_body.txt 
  0|/Documents and Settings ($FILE_NAME)|80328-48-2|d/dr-xr-xr-x|0|0|110|1596318524|1596318524|1596318524|1596318524
  0|/Documents and Settings|80328-144-1|d/dr-xr-xr-x|0|0|48|1596318524|1596318524|1596318524|1596318524
  0|/ProgramData ($FILE_NAME)|237-48-2|d/dr-xr-xr-x|0|0|88|1596321975|1596321975|1596321975|1596321975

The mactime command takes in a body file with -b and then parses the body file and output a timeline to std output. Using -d for delimited we can redirect the output into a csv file to be viewed in Timeline Explorer or Excel.

  mactime -d -b SUSPECT_body.txt > SUSPECT_timeline.csv
  
  head SUSPECT_timeline.csv 
  Date,Size,Type,Mode,UID,GID,Meta,File Name
  Mon Dec 31 1979 23:00:00,173,m...,r/rrwxrwxrwx,0,0,108636-128-1,"/Users/anit.ghosh/AppData/Local/Google/Chrome/User Data/FileTypePolicies/43/manifest.json"
  Mon Dec 31 1979 23:00:00,76,m...,r/rrwxrwxrwx,0,0,108661-128-1,"/Users/anit.ghosh/AppData/Local/Google/Chrome/User Data/SSLErrorAssistant/7/manifest.json"
  Mon Dec 31 1979 23:00:00,1765,m...,r/rrwxrwxrwx,0,0,108663-128-4,"/Users/anit.ghosh/AppData/Local/Google/Chrome/User Data/SSLErrorAssistant/7/_metadata/verified_contents.json"
```
### MFT
MFT stands for Master File Table and contains records of all of the files within an NTFS volume. Being able to parse this data to find information on the file you are looking for is very valaubleto an investigator.

I gave the example earlier on how to extract the $MFT file with icat (icat -o 1126400 SUSPECT.raw 0-128-6 > MFT.raw). Now to parse it using the ntfs_parser script from ntfs_dfir. This tool can parse other important ntfs artifacts as well.
```
ntfs_parser -h
Extract information from NTFS metadata files, volumes, and shadow copies

Usage:
 ntfs_parser --mft <input file ($MFT)> <output file (CSV)>
 ntfs_parser --usn <input file ($MFT)> <input file ($UsnJrnl:$J)> <output file (CSV)>
 ntfs_parser --log <input file ($MFT)> <input file ($LogFile)> <output file (TXT)>
 ntfs_parser --indx <input file (raw image)> <volume offset (in bytes)> <output file (CSV)>
 ntfs_parser --all-mft <input file (raw image)> <volume offset (in bytes)> <output file (CSV)>
 ntfs_parser --mem <input file (raw memory image)> <output file (CSV)>
 ntfs_parser --move <input file (tracking.log)> <output file (TXT)>

---------------------------------------------------------------------------------------------

ntfs_parser --mft MFT.raw MFT_parsed.csv
```
Now we have a file we can view in our favorite csv tool.

## Triage
Its good to start off with a general triage of the disk and contents before diving in to see if anything sticks out.

#### C Directory
* Documents and Settings
      * This points to an older operating system like Windows Vista
* Recycle.Bin
  * Nothing interesting in Recycle Bin
  ```
      fls -r -o 1126400 SUSPECT.raw 58-144-5                                               
      d/d 81885-144-1:	S-1-5-18
      + r/r 81886-128-1:	desktop.ini
      d/d 84670-144-1:	S-1-5-21-3064058907-2826536974-2889819764-1106
      + r/r 84671-128-1:	desktop.ini
      d/d 85947-144-1:	S-1-5-21-3064058907-2826536974-2889819764-500
      + r/r 85948-128-1:	desktop.ini
      d/d 81091-144-1:	S-1-5-21-672274782-2342008316-3472871522-1000
      + r/r 81092-128-1:	desktop.ini
      d/d 81805-144-1:	S-1-5-21-672274782-2342008316-3472871522-1001
      + r/r 81806-128-1:	desktop.ini
      d/d 79320-144-1:	S-1-5-21-846388080-3680834429-2020154290-1001
      + r/r 80352-128-1:	desktop.ini
  ```
      
#### Anit Ghosh Directory
I am using the below command to list the contents of anit.ghosh user directory 2 levels deep to help get an idea of any personal files and applications the user has.
```
fls -r -D -o 1126400 SUSPECT.raw 83898-144-6 | grep -v '^\(+\)\{3,\}' | less
```
* adstressor
  * This is an interesting directory. It is a git repository for some code this user was working on
  ```
   d/d 855-144-16: adstresser
      + d/d 173737-144-10:    .git
      ++ d/d 173977-144-2:    branches
      ++ d/d 173978-144-8:    hooks
      ++ d/d 173979-144-3:    info
      ++ d/d 173738-144-4:    logs
      ++ d/d 173743-144-18:   objects
      ++ d/d 173980-144-5:    refs
      + d/d 174005-144-3:     gradle
      ++ d/d 174006-144-4:    wrapper
      + d/d 173985-144-3:     src
      ++ d/d 173986-144-5:    main
  ```
* .bash_history contents
  * Nothing special here
  ```
  icat -o 1126400 SUSPECT.raw 86752-128-1
  sudo su
  ```
* AppData Roaming Applications
  * Thunderbird is an email client meaning some email data might be stored on in the file system
  ```
   d/d 83910-144-5:      Roaming
      ++ d/d 84335-144-1:     Adobe
      ++ d/d 93585-144-5:     Code
      ++ d/d 83911-144-6:     Microsoft
      ++ d/d 85257-144-1:     Mozilla
      ++ d/d 108496-144-1:    Sun
      ++ d/d 85224-144-6:     Thunderbird
      ++ d/d 80587-144-5:     VSCodium
  ```
* SDelete.exe
  * This is a file deletion tool
  ```
  d/d 83908-144-1:        Desktop
      + r/r 84450-128-1:      desktop.ini
      + r/r 170245-128-3:     sdelete.exe
  ```
* Zone Identifier Check
  * This command goes 3 directory levels deep and looks for files with the Zone.Identifier alternate data stream that shows they were downloaded from the Internet
  * fls -rp -o 1126400 SUSPECT.raw 83898-144-6 | grep -E '^([^/]*\/){0,3}[^/]*$' | grep -i "Zone" | less
  * VSCodium and Git aren't very interesting but Doc_-_13_Feb_2021_-_13-40.pdf and xraicommend-761263a55b8cfed4bcb8f87cbbb68beaf2ec2423.tar.gz are interesting
  ```
      r/r 110269-128-4:       Documents/Doc_-_13_Feb_2021_-_13-40.pdf:Zone.Identifier
      r/r 90201-128-5:        Documents/VSCodium-win32-ia32-1.53.2/chrome_100_percent.pak:Zone.Identifier
      r/r 90202-128-5:        Documents/VSCodium-win32-ia32-1.53.2/chrome_200_percent.pak:Zone.Identifier
      r/r 90203-128-5:        Documents/VSCodium-win32-ia32-1.53.2/d3dcompiler_47.dll:Zone.Identifier
      r/r 90204-128-4:        Documents/VSCodium-win32-ia32-1.53.2/ffmpeg.dll:Zone.Identifier
      r/r 90205-128-4:        Documents/VSCodium-win32-ia32-1.53.2/icudtl.dat:Zone.Identifier
      r/r 90206-128-4:        Documents/VSCodium-win32-ia32-1.53.2/libEGL.dll:Zone.Identifier
      r/r 90207-128-5:        Documents/VSCodium-win32-ia32-1.53.2/libGLESv2.dll:Zone.Identifier
      r/r 92016-128-5:        Documents/VSCodium-win32-ia32-1.53.2/resources.pak:Zone.Identifier
      r/r 92017-128-5:        Documents/VSCodium-win32-ia32-1.53.2/snapshot_blob.bin:Zone.Identifier
      r/r 92024-128-5:        Documents/VSCodium-win32-ia32-1.53.2/v8_context_snapshot.bin:Zone.Identifier
      r/r 92025-128-5:        Documents/VSCodium-win32-ia32-1.53.2/vk_swiftshader.dll:Zone.Identifier
      r/r 92026-128-4:        Documents/VSCodium-win32-ia32-1.53.2/vk_swiftshader_icd.json:Zone.Identifier
      r/r 92027-128-4:        Documents/VSCodium-win32-ia32-1.53.2/VSCodium.exe:Zone.Identifier
      r/r 88065-128-4:        Documents/VSCodium-win32-ia32-1.53.2/VSCodium.VisualElementsManifest.xml:Zone.Identifier
      r/r 92028-128-4:        Documents/VSCodium-win32-ia32-1.53.2/vulkan-1.dll:Zone.Identifier
      r/r 100286-128-5:       Downloads/Git-2.30.1-32-bit.exe:Zone.Identifier
      r/r 170295-128-8:       Downloads/SDelete.zip:Zone.Identifier
      r/r 58234-128-9:        Downloads/xraicommend-761263a55b8cfed4bcb8f87cbbb68beaf2ec2423.tar.gz:Zone.Identifier
  ```
#### Timeline
* Lots of Google Chrome AppData files written to (Likely anit.ghosh's main browser)
* Adstressor directory activity - Wed Feb 10 2021 06:54:13 (actively making changes to repository)
```
/Users/anit.ghosh/adstresser/.git/objects/9d
/Users/anit.ghosh/adstresser/.git/objects/9d ($FILE_NAME)
/Users/anit.ghosh/adstresser/.git/objects/08
/Users/anit.ghosh/adstresser/.git/objects/08 ($FILE_NAME)
/Users/anit.ghosh/adstresser/.git/objects/9d/02a09103ff2ddb584b284a32da82186d8f101d
/Users/anit.ghosh/adstresser/.git/objects/9d/02a09103ff2ddb584b284a32da82186d8f101d ($FILE_NAME)
/Users/anit.ghosh/adstresser/.git/objects/08/bca1dbc17adfc214f8d40c57673e0571914ac1
/Users/anit.ghosh/adstresser/.git/objects/08/bca1dbc17adfc214f8d40c57673e0571914ac1 ($FILE_NAME)
/Users/anit.ghosh/adstresser/.git/objects/5e/0ef19dd64d7aa45781bf2625abf5c648020ccd
/Users/anit.ghosh/adstresser/.git/objects/5e/0ef19dd64d7aa45781bf2625abf5c648020ccd ($FILE_NAME)
/Users/anit.ghosh/adstresser/.git/logs/refs/remotes/origin/HEAD
/Users/anit.ghosh/adstresser/.git/logs/refs/remotes/origin/HEAD ($FILE_NAME)
/Users/anit.ghosh/adstresser/.git/logs/refs/remotes/origin/wip
/Users/anit.ghosh/adstresser/.git/logs/refs/remotes/origin/wip ($FILE_NAME)
/Users/anit.ghosh/adstresser/.git/refs/remotes/origin/HEAD
/Users/anit.ghosh/adstresser/.git/refs/remotes/origin/HEAD ($FILE_NAME)
/Users/anit.ghosh/adstresser/.git/refs/remotes/origin/wip
/Users/anit.ghosh/adstresser/.git/refs/remotes/origin/wip ($FILE_NAME)
```
## Questions
1. What is the full name of the laptop owner?
Normally when I want to find out owner I check the version key in the SOFTWARE hive. This shows the RegisteredOwner is User instead of anit.ghosh like I had originally thought. It also shows this is a Windows 10 OS so I was incorrect about this being an older system because of the Documents and Settings folder I saw earlier.
```
./rip.pl -r ~/Downloads/SUSPECT_Evidence/SOFTWARE.raw -p winver
Launching winver v.20200525
winver v.20200525
(Software) Get Windows version & build info

ProductName               Windows 10 Enterprise LTSC 2019
ReleaseID                 1809                
BuildLab                  17763.rs5_release.180914-1434
BuildLabEx                17763.1.x86fre.rs5_release.180914-1434
CompositionEditionID      EnterpriseS         
RegisteredOrganization                        
RegisteredOwner           User                
UBR                       1757                
InstallDate               2020-08-01 18:49:09Z
InstallTime               2020-08-01 18:49:09Z
UBR                       1757                
```
This got me curious about user activity so looking at last logged on user... we can see it is in fact anit.ghosh
```
./rip.pl -r ~/Downloads/SUSPECT_Evidence/SOFTWARE.raw -p lastloggedon
Launching lastloggedon v.20200517
lastloggedon v.20200517
(Software) Gets LastLoggedOn* values from LogonUI key

LastLoggedOn
Microsoft\Windows\CurrentVersion\Authentication\LogonUI
LastWrite: 2021-02-14 02:32:42Z

LastLoggedOnUser    = PRAIVACYMATRIX\anit.ghosh
LastLoggedOnSAMUser = PRAIVACYMATRIX\anit.ghosh
LastLoggedOnUserSID = S-1-5-21-3064058907-2826536974-2889819764-1106
```
Next I checked the SAM hive to get information on all system users and was surprised to see User was only active account and anit.ghosh is not mentioned anywhere. 
```
./rip.pl -r ~/Downloads/SUSPECT_Evidence/SAM.raw -p samparse

...

Username        : User [1001]
SID             : S-1-5-21-672274782-2342008316-3472871522-1001
Full Name       : 
User Comment    : 
Account Type    : 
Account Created : Sat Aug  1 18:50:19 2020 Z
Name            :  
Last Login Date : Sat Aug  1 21:17:25 2020 Z
Pwd Reset Date  : Never
Pwd Fail Date   : Never
Login Count     : 6
  --> Normal user account
  --> Password not required
  --> Password does not expire
```
Then I realized from the lastloggedon check that anit.ghosh is a domain user from the PRAIVACYMATRIX domain instead of a local user so it wouldn't appear in the SAM hive.

That was a little more than necessary but I will say that **Anit Ghosh** is the laptop owner.

2. What is the full address of company's office? Full address line incl. country name
At first I thought maybe looking at some of the documents could reveal this information but couldn't find anything. Then I thought maybe a company website could provide an address. The tool I am going to use is Bulk Extractor which is a useful tool for extracting email address, urls, phone number, and other formatted data from a disk image. 
```
bulk_extractor -o bulk_SUSPECT SUSPECT.raw
mkdir "bulk.
_SUSPECT"
bulk_extractor version: 2.1.1
Input file: "SUSPECT.raw"
Output directory: "bulk_SUSPECT"
Disk Size: 42949672960
Scanners: aes base64 elf evtx exif facebook find gzip httplogs json km_carved msxml net ntfs rved windirs winlnk winpe winprefetch zip accts email gps
Threads: 8
going multi-threaded... ( 8)
bulk_extractor
Mon Jun 24 18:38:38 2024
```
First I looked at the domain histogram and nothing stuck out so then I looked at the email_domain_histogram.
```
cat ../bulk_SUSPECT/email_domain_histogram.txt | head
# BANNER FILE NOT PROVIDED (-b option)
# BULK_EXTRACTOR-Version: 2.1.1
# Feature-Recorder: email
# Filename: SUSPECT.raw
# Histogram-File-Version: 1.1
n=1332	@gmail.com
n=1147	@openssh.com
n=759	@praivacymatrix.com	(utf16=12)
n=526	@vim.org
n=386	@apache.org
```
Here we can see the praivacymatrix.com domain just like we saw earlier with the user logon. If you try to navigate to or search for this website you won't find anything because this challenge is now over 3 years old. But nothing on the Internet ever disapears. Looking up this wesbite up on the Wayback Machine gives us what we are looking for. It shows it was active until February of 2024 so just recently removed. You can find it at https://web.archive.org/web/20220314080131/https://praivacymatrix.com/ and under the Contact Us portion is the company address.

Address: **Ifangstrasse 6, 8952 Schlieren, Zurich, Switzerland**

3. On November 16th security department got a signal of unauthorized attempts to obtain company's trade secrets. When did the suspect first show interest in those? Provide exact timestamp in a common format, e.g. 2021-07-07 17:07:07 UTC

My first idea was to check his browsing activity to see if that could provide any hints. So I extracted anit.ghosh Chrome History db and opened it using sqlite3. Checking the url history provided some suspicous data exfiltration activity below.

select url, title, last_visit_time from urls order by last_visit_time desc;
```
url|title|last_visit_time
https://stackoverflow.com/questions/28160254/7-zip-command-to-create-and-extract-a-password-protected-zip-file-on-windows|encryption - 7-Zip command to create and extract a password-protected ZIP file on Windows? - Stack Overflow|13257743688675531
https://gofile.io/welcome|Gofile|13257743687361975
https://anonfiles.com/|Anonymous File Upload - AnonFiles|13257743686088732
https://filebin.net/|Filebin|13257743685952182
http://ci.pm.internal/wstarnes/|/wstarnes/ — PM Continuous Integration|13257743684408170
https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete|SDelete - Windows Sysinternals | Microsoft Docs|13257743682978538
https://www.google.com/search?q=windows+secure+file+delete&oq=windows+secure+file+de&aqs=chrome.0.0i19j69i57j0i19i22i30l2.173735j0j7&sourceid=chrome&ie=UTF-8|windows secure file delete - Поиск в Google|13257742927280896
http://anonfiles.com/|Anonymous File Upload - AnonFiles|13257742416528574
https://gofile.io/|Gofile|13257742404218190
https://www.google.com/search?q=anonymous+file+upload&oq=anonymous+file+upload&aqs=chrome..69i57j0i22i30l9.9613j1j7&sourceid=chrome&ie=UTF-8|anonymous file upload - Поиск в Google|13257742380625770
https://www.google.com/search?q=7z+pack+with+password&oq=7z+pack+with+pass&aqs=chrome.1.69i57j33i22i29i30.23471j0j7&sourceid=chrome&ie=UTF-8|7z pack with password - Поиск в Google|13257742363694331
http://git.pm.internal/user/login|git.pm.internal|13257742238612426
http://git.pm.internal/GBringley/xraicommend/archive/761263a55b8cfed4bcb8f87cbbb68beaf2ec2423.tar.gz|Sign In - prAIvacy mAtrIx Git|13257742238612426
https://mail.protonmail.com/login|Login | ProtonMail|13257460516258034
https://protonmail.com/|Secure email: ProtonMail is free encrypted email.|13257460511111168
https://stackoverflow.com/questions/20318770/send-mail-from-linux-terminal-in-one-line|email - send mail from linux terminal in one line - Stack Overflow|13257460490626523
https://www.google.com/search?q=linux+send+mail+from+command+line&oq=linux+send+mail+fro&aqs=chrome.3.69i57j0l7.8387j0j7&sourceid=chrome&ie=UTF-8|linux send mail from command line - Поиск в Google|13257460487704334
https://tecadmin.net/ways-to-send-email-from-linux-command-line/|5 Ways To Send Email from Linux Command Line - TecAdmin|13257460482004271
https://stackoverflow.com/questions/17548064/how-to-have-a-bash-script-loop-until-a-specific-time|How to have a bash script loop until a specific time - Stack Overflow|13257460461514430
```
Here is a summary of what I see
* Writing a bash script to run at a cetain time and send an email which is not guarenteed to be malicious but in this case likely is
* 761263a55b8cfed4bcb8f87cbbb68beaf2ec2423.tar.gz We saw this file earlier in the Downloads folder
* Search for an anonymous file upload
* Figuring out how to securely delete a file
* Extracting a password from a zip file
My guess from this information anit.ghosh attempted to insert a backdoor into some code to send emails later on, then downloads the source code, uploads it to a site, then deletes something with SDelete. I haven't come across a zip file yet but now I will start keeping an eye out.

This leads us to the source code but nothing about the technical documentation. We need to keep looking.

Next I will check his email. If you remember earlier Thunderbird was installed which is a local email client meaning there are likely some emails on the disk. I do a grep search and find a directory I believe should contain the local mail.
```
fls -rp -o 1126400 SUSPECT.raw | grep -i "/mail"
d/d 85116-144-6:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix-1.com
r/r 86348-128-4:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix-1.com/Archives.msf
r/r 86346-128-4:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix-1.com/Drafts-1.msf
r/r 86297-128-4:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix-1.com/Drafts.msf
r/r 86182-128-1:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix-1.com/filterlog.html
r/r 86349-128-3:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix-1.com/INBOX
r/r 86254-128-4:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix-1.com/INBOX.msf
r/r 86345-128-4:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix-1.com/Junk.msf
r/r 86342-128-1:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix-1.com/msgFilterRules.dat
r/r 86350-128-3:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix-1.com/Sent-1
r/r 86343-128-4:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix-1.com/Sent-1.msf
r/r 86338-128-4:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix-1.com/Sent.msf
r/r 86306-128-5:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix-1.com/Templates.msf
r/r 86344-128-4:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix-1.com/Trash.msf
r/r 84753-128-5:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix-1.com.msf
d/d 84913-144-6:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix.com
r/r 86236-128-4:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix.com/Archives.msf
r/r 86239-128-4:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix.com/Drafts.msf
r/r 86242-128-1:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix.com/filterlog.html
r/r 86237-128-5:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix.com/INBOX.msf
r/r 86228-128-1:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix.com/msgFilterRules.dat
r/r 86241-128-4:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix.com/Sent.msf
r/r 86240-128-5:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix.com/Templates.msf
r/r 86227-128-5:	Users/anit.ghosh/AppData/Roaming/Thunderbird/Profiles/0i8ga8eq.default-release/ImapMail/mail.praivacymatrix.com.msf
```
I am going to start by looking at his sent mail in the Sent-1 file at inode 86350-128-3.
```
cat Sent-1 | less
------------------------------------------------------------------------
To: "john.finney@praivacymatrix.com" <john.finney@praivacymatrix.com>
From: <anit.ghosh@praivacymatrix.com>
Subject: Technical documentation
Date: Thu, 05 Nov 2020 14:21:56 -0500
Importance: normal
X-Priority: 3
Content-Type: multipart/alternative;
        boundary="_6DB6798A-AD6D-4A52-9683-D05C653F02EA_"

--_6DB6798A-AD6D-4A52-9683-D05C653F02EA_
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset="utf-8"

Hey John,

I've been requested to review a couple of files. But unfortunately, I could=
n't find the last file in the list - new technical documentation.=20

Could you help me find this file and send it to me? I would be very grateful!

Anit Ghosh.
```
Scrolling through we find evidence of Anit reaching out to people for the technical documentation. Here is the earliest email, sent to John on 05 Nov 2020 14:21:56 -0500.

In the specified format it would be **2021-07-07 17:07:07 UTC**.

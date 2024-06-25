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

Looking at the output there are two NTFS partitions to look at to determine the main volume. To look into further into each partion I will use the fls command. To view each partition provide the starting sector offset for each partition.

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
Viewing the file contents of each of these partitions shows the second one with a starting sector offset of 1126400 is the main volume we will want to be looking at containing user information.

To navigate through the file system you take can use the icat command to output the contents of the file or you can use the fls command to navigate throught the directories. To do this you need to provide the inode to the end of the command. This can be found in the second column ofthe fls output.

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

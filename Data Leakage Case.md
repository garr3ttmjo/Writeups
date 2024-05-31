Questions

#### 1. What are the hash values (MD5 & SHA-1) of all images?

Path and  File Name | MD5 Hash | SHA256 Hash
--- | --- | --- |
cfreds_2015_data_leakage_pc/cfreds_2015_data_leakage_pc.dd | a49d1254c873808c58e6f1bcd60b5bde | afe5c9ab487bd47a8a9856b1371c2384d44fd785
RM1/cfreds_2015_data_leakage_rm#1.E01 | 7cd7bc148d3a1e5f329cb3580d4d4f8f | ffd0f3cba3dfe3291f786b845a06a8aa56c1cd8c
RM2/cfreds_2015_data_leakage_rm#2.dd | b4644902acab4583a1d0f9f1a08faa77 | 048961a85ca3eced8cc73f1517442d31d4dca0a3
RM3/cfreds_2015_data_leakage_rm#3_type2.dd | 858c7250183a44dd83eb706f3f178990 | 471d3eedca9add872fc0708297284e1960ff44f8

#### 2. Does the acquisition and verification hash value match?
#### 3. Identify the partition information of PC image.

Using the mmls command from Sleuthkit we can see the partition data for the image.
```
mmls cfreds_2015_data_leakage_pc.dd
	 	
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors
      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)
003:  000:001   0000206848   0041940991   0041734144   NTFS / exFAT (0x07)
004:  -------   0041940992   0041943039   0000002048   Unallocated
```
Going a bit further with Sleuthkit tools we can take a closer look into these partitions and which ones will likely be important. The fls command will take the beginning sector offset of a partition and show the contents. This shows the partition starting at sector 2048 is the boot partition.
```
fls -o 2048 cfreds_2015_data_leakage_pc.dd

r/r 4-128-4:    $AttrDef
r/r 8-128-2:    $BadClus
r/r 8-128-1:    $BadClus:$Bad
r/r 6-128-4:    $Bitmap
r/r 7-128-1:    $Boot
d/d 11-144-4:   $Extend
r/r 2-128-1:    $LogFile
r/r 0-128-1:    $MFT
r/r 1-128-1:    $MFTMirr
r/r 9-128-8:    $Secure:$SDS
r/r 9-144-11:   $Secure:$SDH
r/r 9-144-14:   $Secure:$SII
r/r 10-128-1:   $UpCase
r/r 3-128-3:    $Volume
d/d 35-144-5:   Boot
r/r 85-128-1:   bootmgr
r/r 96-128-3:   BOOTSECT.BAK
d/d 97-144-1:   System Volume Information
V/V 256:        $OrphanFiles
```
Looking at the next partition starting with sector 206848 we can see this is the main NTFS partition we should be investigating.
```
fls -o 206848 cfreds_2015_data_leakage_pc.dd

d/d 486-144-5:  Users
d/d 13797-144-1:        Documents and Settings
d/d 389-144-6:  ProgramData
d/d 273-144-6:  Program Files (x86)
r/r 4-128-4:    $AttrDef
r/r 8-128-2:    $BadClus
r/r 8-128-1:    $BadClus:$Bad
r/r 6-128-4:    $Bitmap
r/r 7-128-1:    $Boot
d/d 11-144-4:   $Extend
r/r 2-128-1:    $LogFile
r/r 0-128-1:    $MFT
r/r 1-128-1:    $MFTMirr
d/d 57-144-5:   $Recycle.Bin
r/r 9-128-8:    $Secure:$SDS
r/r 9-144-16:   $Secure:$SDH
r/r 9-144-17:   $Secure:$SII
r/r 10-128-1:   $UpCase
r/r 3-128-3:    $Volume
d/d 71980-144-6:        Config.Msi
d/d 22329-144-1:        MSOCache
d/d 58-144-1:   PerfLogs
d/d 60-144-6:   Program Files
r/- * 15512:    WIMECB2.tmp
r/- * 15513:    WIMECC3.tmp
r/- * 15514:    WIMECF3.tmp
r/- * 15515:    WIMECF4.tmp
r/- * 15516:    WIMED24.tmp
r/- * 15517:    WIMED63.tmp
r/- * 15700:    WIMF282.tmp
r/- * 15701:    WIMF283.tmp
r/- * 15703:    WIMF2A4.tmp
r/- * 15704:    WIMF2A5.tmp
r/- * 15705:    WIMF2A6.tmp
r/- * 54:       WinPEpge.sys
d/d 21667-144-1:        Recovery
d/d 58992-144-6:        System Volume Information
r/- * 0:        WIMF32B.tmp
r/- * 0:        WIMF33C.tmp
r/- * 15903:    WIMF5BD.tmp
r/- * 15904:    WIMF5BE.tmp
r/- * 15905:    WIMF5BF.tmp
r/- * 15936:    WIMF5C0.tmp
r/- * 15937:    WIMF5C1.tmp
r/- * 15938:    WIMF5D1.tmp
r/- * 15939:    WIMF5D2.tmp
r/- * 15940:    WIMF5D3.tmp
r/- * 15941:    WIMF5D4.tmp
r/- * 15945:    WIMF5D5.tmp
r/- * 15946:    WIMF5D6.tmp
r/- * 15947:    WIMF5D7.tmp
r/- * 15948:    WIMF913.tmp
r/- * 15949:    WIMF914.tmp
r/- * 15950:    WIMFA8B.tmp
r/- * 15951:    WIMFA8C.tmp
r/- * 0:        WinPEpge.sys
-/d * 75543-144-1:      Config.Msi
d/d 650-144-5:  Windows
V/V 78080:      $OrphanFiles
r/r 504-128-1:  hiberfil.sys
r/r 58995-128-1:        pagefile.sys
```

#### 4. Explain installed OS information in detail. (OS name, install date, registered owner…)

Easy way to do this is to use Regripper with the winver plugin 
```
rip.exe -r "D:\Data Leakage Case\Kape Triage\G\Windows\System32\config\SOFTWARE" -p winver

Launching winver v.20200525
winver v.20200525
(Software) Get Windows version & build info

ProductName               Windows 7 Ultimate
CSDVersion                Service Pack 1
BuildLab                  7601.win7sp1_gdr.130828-1532
BuildLabEx                7601.18247.amd64fre.win7sp1_gdr.130828-1532
RegisteredOrganization
RegisteredOwner           informant
InstallDate               2015-03-22 14:34:26Z
```
This same information can be found at the SOFTWARE\Microsoft\Windows NT\CurrentVersion registry key using a tool like Registry Explorer.

![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/450a88f2-024a-4e51-82da-7a800180c528)

Use Registry Explorer's Data Interpreter to view the Install Date into a readable format.

![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/628fdb62-f0d8-4425-bddd-0571bab76d34)

Here is a link that compares Windows 7 Ultimate from the other Windows 7 OS. https://www.tutorialspoint.com/difference-between-ultimate-and-enterprise-windows-7

#### 5. What is the timezone setting?
Using Regripper with timezone plugin retrieves the information from System\ControlSet001\Control\TimeZoneInformation key for Eastern Standard Time.
```
rip.exe -r "D:\Cases\NIST\Data Leakage Case\Kape Triage\G\Windows\System32\config\SYSTEM" -p timezone

Launching timezone v.20200518
timezone v.20200518
(System) Get TimeZoneInformation key contents

TimeZoneInformation key
ControlSet001\Control\TimeZoneInformation
LastWrite Time 2015-03-25 10:34:25Z
  DaylightName   -> @tzres.dll,-111
  StandardName   -> @tzres.dll,-112
  Bias           -> 300 (5 hours)
  ActiveTimeBias -> 240 (4 hours)
  TimeZoneKeyName-> Eastern Standard Time
```
#### 6. What is the computer name?
This information is stored at System\ControlSet001\Control\ComputerName\ComputerName to give us INFORMANT-PC.
```
rip.exe -r "D:\Cases\NIST\Data Leakage Case\Kape Triage\G\Windows\System32\config\SYSTEM" -p compname
Launching compname v.20090727
compname v.20090727
(System) Gets ComputerName and Hostname values from System hive

ComputerName    = INFORMANT-PC
TCP/IP Hostname = informant-PC
```
#### 7. List all accounts in OS except the system accounts: Administrator, Guest, systemprofile, LocalService, NetworkService. (Account name, login count, last logon date…)
This information is found in the SAM hive at SAM\SAM\Domains\Account\Users. Its not easy to view in Registry Explorer so best to export it and then view in Timeline Explorer or Excel.

![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/83387bf1-af3e-4012-a6be-9046684651eb)

	User Name
	1. informant
	1. admin11
	1. ITechTeam
	1. temporary

#### 8. Who was the last user to logon into PC?
![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/bd1edb0a-20bf-4844-9167-49814819ffad)

informant at 2015-03-25 14:45:59

#### 9. When was the last recorded shutdown date/time?
Shutdown subkey found at System\ControlSet001\Control\Windows.
```
rip.exe -r "D:\Cases\NIST\Data Leakage Case\Kape Triage\G\Windows\System32\config\SYSTEM" -p shutdown

Launching shutdown v.20200518
shutdown v.20200518
(System) Gets ShutdownTime value from System hive

ControlSet001\Control\Windows key, ShutdownTime value
LastWrite time: 2015-03-25 15:31:05Z
ShutdownTime  : 2015-03-25 15:31:05Z
```
15. Explain the information of network interface(s) with an IP address assigned by DHCP.
1. What applications were installed by the suspect after installing OS?
1. List application execution logs. (Executable path, execution time, execution count...)
1. List all traces about the system on/off and the user logon/logoff. (It should be considered only during a time range between 09:00 and 18:00 in the timezone from Question 4.)
1. What web browsers were used?
1. Identify directory/file paths related to the web browser history.
1. What websites were the suspect accessing? (Timestamp, URL...)
1. List all search keywords using web browsers. (Timestamp, URL, keyword...)
1. List all user keywords at the search bar in Windows Explorer. (Timestamp, Keyword)
1. What application was used for e-mail communication?
1. Where is the e-mail file located?
1. What was the e-mail account used by the suspect?
1. List all e-mails of the suspect. If possible, identify deleted e-mails. (You can identify the following items: Timestamp, From, To, Subject, Body, and Attachment) [Hint: just examine the OST file only.]
1. List external storage devices attached to PC.
1. Identify all traces related to ‘renaming’ of files in Windows Desktop. (It should be considered only during a date range between 2015-03-23 and 2015-03-24.)[Hint: the parent directories of renamed files were deleted and their MFT entries were also overwritten. Therefore, you may not be able to find their full paths.]
1. What is the IP address of company’s shared network drive?
1. List all directories that were traversed in ‘RM#2’.
1. List all files that were opened in 'RM#2’.
1. List all directories that were traversed in the company’s network drive.
1. List all files that were opened in the company’s network drive.
1. Find traces related to cloud services on PC. (Service name, log files...)
1. What files were deleted from Google Drive?
1. Find the filename and modified timestamp of the file. [Hint: Find a transaction log file of Google Drive.]
1. Identify account information for synchronizing Google Drive.
1. What a method (or software) was used for burning CD-R?
1. When did the suspect burn CD-R? [Hint: It may be one or more times.]
1. What files were copied from PC to CD-R? [Hint: Just use PC image only. You can examine transaction logs of the file system for this task.]
1. What files were opened from CD-R?
1. Identify all timestamps related to a resignation file in Windows Desktop. [Hint: the resignation file is a DOCX file in NTFS file system.]
1. How and when did the suspect print a resignation file?
1. Where are ‘Thumbcache’ files located?
1. Identify traces related to confidential files stored in Thumbcache. (Include ‘256’ only)
1. Where are Sticky Note files located?
1. Identify notes stored in the Sticky Note file.
1. Was the ‘Windows Search and Indexing’ function enabled? How can you identify it?
1. If it was enabled, what is a file path of the ‘Windows Search’ index database?
1. What kinds of data were stored in Windows Search database?
1. Find traces of Internet Explorer usage stored in Windows Search database. (It should be considered only during a date range between 2015-03-22 and 2015-03-23.)
1. List the e-mail communication stored in Windows Search database. (It should be considered only during a date range between 2015-03-23 and 2015-03-24.)
1. List files and directories related to Windows Desktop stored in Windows Search database. (Windows Desktop directory: \Users\informant\Desktop\)
1. Where are Volume Shadow Copies stored? When were they created?
1. Find traces related to Google Drive service in Volume Shadow Copy.
1. What are the differences between the current system image (of Question 29 ~ 31) and its VSC?
1. What files were deleted from Google Drive?
1. Find deleted records of cloud_entry table inside snapshot.db from VSC. (Just examine the SQLite database only. Let us suppose that a text based log file was wiped.) [Hint: DDL of cloud_entry table is as follows.]
         CREATE TABLE cloud_entry
         (doc_id TEXT, filename TEXT, modified INTEGER, created INTEGER, acl_role INTEGER,
         doc_type INTEGER, removed INTEGER, size INTEGER, checksum TEXT, shared INTEGER,
		     resource_type TEXT, PRIMARY KEY (doc_id));
1. Why can’t we find Outlook’s e-mail data in Volume Shadow Copy?
1. Examine ‘Recycle Bin’ data in PC.
1. What actions were performed for anti-forensics on PC at the last day '2015-03-25'?
1. Recover deleted files from USB drive ‘RM#2’.
1. What actions were performed for anti-forensics on USB drive ‘RM#2’? [Hint: this can be inferred from the results of Question 53.]
1. What files were copied from PC to USB drive ‘RM#2’?
1. Recover hidden files from the CD-R ‘RM#3’.
1. How to determine proper filenames of the original files prior to renaming tasks?
1. What actions were performed for anti-forensics on CD-R ‘RM#3’?
1. Create a detailed timeline of data leakage processes.
1. List and explain methodologies of data leakage performed by the suspect.
1. Create a visual diagram for a summary of results.

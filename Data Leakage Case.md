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
#### 10. Explain the information of network interface(s) with an IP address assigned by DHCP.
The SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards\ key shows the Network Interface Cards for the system but on this system there is just one.

![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/bbfd32f3-c7ff-43c7-ac99-5655797bbe8a)

Then we can look at the ControlSet001\Services\Tcpip\Parameters\Interfaces key and match the adapter id {E2B9AEEC-B1F7-4778-A049-50D7F2DAB2DE} to get the DHCP information.
```
rip.exe -r "D:\Cases\NIST\Data Leakage Case\Kape Triage\G\Windows\System32\config\SYSTEM" -p nic2
Launching nic2 v.20200525
nic2 v.20200525
(System) Gets NIC info from System hive

Adapter: {846ee342-7039-11de-9d20-806e6f6e6963}
LastWrite Time: 2015-03-25 10:33:18Z

ControlSet001\Services\Tcpip\Parameters\Interfaces has no subkeys.
Adapter: {E2B9AEEC-B1F7-4778-A049-50D7F2DAB2DE}
LastWrite Time: 2015-03-25 15:24:51Z
  DhcpIPAddress                10.11.11.129
  DhcpSubnetMask               255.255.255.0
  DhcpServer                   10.11.11.254
  Lease                        1800
  LeaseObtainedTime            2015-03-25 15:19:50Z
  T1                           2015-03-25 15:34:50Z
  T2                           2015-03-25 15:46:05Z
  LeaseTerminatesTime          2015-03-25 15:49:50Z
  DhcpGatewayHardwareCount     1
  DhcpNameServer               10.11.11.2
  DhcpDefaultGateway           10.11.11.2
  DhcpDomain                   localdomain
  DhcpSubnetMaskOpt            255.255.255.0
```
From these two keys we can see we have a Intel(R) PRO/1000 MT Network Connection NIC with a DhcpIPAddress of 10.11.11.129.

#### 11. What applications were installed by the suspect after installing OS?
There are a few ways to find the answer to this question. Something I like to do is a quick scan to see what files have a Zone.Identifier of 3 which means they were downloaded from the internet. Here you can see I find 6 .exe files that were downloaded.
```
fls -r -o 206848 cfreds_2015_data_leakage_pc.dd | rg  "Zone.Identifier"

++++ r/r 62436-128-4:   IE11-Windows6.1-x64-en-us.exe:Zone.Identifier
++++ -/r * 75101-128-5: Eraser 6.2.0.2962.exe:Zone.Identifier
++++ -/r * 75186-128-5: ccsetup504.exe:Zone.Identifier
+++ r/r 72145-128-8:    googledrivesync.exe:Zone.Identifier
+++ r/r 72096-128-8:    icloudsetup.exe:Zone.Identifier
++ -/r * 74418-128-4:   $RJEMT64.exe:Zone.Identifier
-----------------------------------------------------------------------------------------
/Users/informant/Desktop/Download/IE11-Windows6.1-x64-en-us.exe - Internet Explorer 11
/Users/informant/Desktop/Download/Eraser 6.2.0.2962.exe - Eraser
/Users/informant/Desktop/Download/ccsetup504.exe - CCleaner
/Users/informant/Downloads/googledrivesync.exe - Google Drive
/Users/informant/Downloads/icloudsetup.exe - iCloud
$RJEMT64.exe - The $R shows this is a "deleted" file in the recycle bin which should have a corresponding $I file containing metadata on the file like its name and path.
If you are not sure where this file is coming from you can use the ffind command to give you the file path from the inode which is how I found the paths of all the .exe above.

ffind -a -o 206848 cfreds_2015_data_leakage_pc.dd 74418-128-1
/$Recycle.Bin/S-1-5-21-2425377081-3129163575-2985601102-1000/$RJEMT64.exe

Using the TSK command icat I can parse out the contents of the corresponding $I file, $IJEMT64.exe.
icat -o 206848 cfreds_2015_data_leakage_pc.dd 74761-128-1
C:\Users\informant\AppData\Local\Microsoft\Windows\Burn\Burn\IE11-Windows6.1-x64-en-us.exe
```
This shows that Internet Explorer was moved to this Burn path and then later deleted. The AppData\Local\Microsoft\Windows\Burn\Burn\ folder is assocaited with the Windows Disc Burning utility so as part of a data exfiltration case we will want to look more into this.

Another way to check for installed programs is to check the Uninstall key in both SOFTWARE and NTUSER.DAT hives.
```
rip.exe -r "D:\Cases\NIST\Data Leakage Case\Kape Triage\G\Windows\System32\config\SOFTWARE" -p uninstall
Launching uninstall v.20200525
uninstall v.20200525
(Software, NTUSER.DAT) Gets contents of Uninstall keys from Software, NTUSER.DAT hives

Uninstall
Microsoft\Windows\CurrentVersion\Uninstall
2015-03-25 14:57:31Z
  Eraser 6.2.0.2962 v.6.2.2962
2015-03-25 14:54:33Z
  Microsoft .NET Framework 4 Extended v.4.0.30319
2015-03-25 14:54:06Z
  Microsoft .NET Framework 4 Extended v.4.0.30319
2015-03-25 14:52:06Z
  Microsoft .NET Framework 4 Client Profile v.4.0.30319
2015-03-25 14:51:39Z
  Microsoft .NET Framework 4 Client Profile v.4.0.30319
2015-03-25 10:15:21Z
  DXM_Runtime
  MPlayer2
2015-03-23 20:00:58Z
  Bonjour v.3.0.0.10
2015-03-22 15:04:14Z
  Microsoft Office Professional Plus 2013 v.15.0.4420.1017
2015-03-22 15:03:33Z
  Microsoft Office Professional Plus 2013 v.15.0.4420.1017
2015-03-22 15:01:46Z
  Microsoft Office 32-bit Components 2013 v.15.0.4420.1017
2015-03-22 15:01:38Z
  Microsoft Word MUI (English) 2013 v.15.0.4420.1017
2015-03-22 15:01:37Z
  Microsoft Outlook MUI (English) 2013 v.15.0.4420.1017
2015-03-22 15:01:34Z
  Microsoft Office OSM MUI (English) 2013 v.15.0.4420.1017
  Microsoft Office OSM UX MUI (English) 2013 v.15.0.4420.1017
2015-03-22 15:01:32Z
  Microsoft Office Proofing (English) 2013 v.15.0.4420.1017
2015-03-22 15:01:31Z
  Microsoft Office Proofing Tools 2013 - English v.15.0.4420.1017
2015-03-22 15:01:30Z
  Outils de v├⌐rification linguistique 2013 de Microsoft Office┬á- Fran├ºais v.15.0.4420.1017
2015-03-22 15:01:14Z
  Microsoft Office Proofing Tools 2013 - Espanol v.15.0.4420.1017
2015-03-22 15:01:13Z
  Microsoft OneNote MUI (English) 2013 v.15.0.4420.1017
2015-03-22 15:01:12Z
  Microsoft Groove MUI (English) 2013 v.15.0.4420.1017
2015-03-22 15:01:11Z
  Microsoft DCF MUI (English) 2013 v.15.0.4420.1017
2015-03-22 15:01:10Z
  Microsoft Publisher MUI (English) 2013 v.15.0.4420.1017
2015-03-22 15:01:09Z
  Microsoft PowerPoint MUI (English) 2013 v.15.0.4420.1017
2015-03-22 15:01:07Z
  Microsoft Excel MUI (English) 2013 v.15.0.4420.1017
2015-03-22 15:01:05Z
  Microsoft Lync MUI (English) 2013 v.15.0.4420.1017
2015-03-22 15:01:04Z
  Microsoft Office Shared 32-bit MUI (English) 2013 v.15.0.4420.1017
2015-03-22 15:01:03Z
  Microsoft InfoPath MUI (English) 2013 v.15.0.4420.1017
2015-03-22 15:01:02Z
  Microsoft Access MUI (English) 2013 v.15.0.4420.1017
  Microsoft Access Setup Metadata MUI (English) 2013 v.15.0.4420.1017
2015-03-22 15:01:01Z
  Microsoft Office Shared Setup Metadata MUI (English) 2013 v.15.0.4420.1017
2015-03-22 15:00:59Z
  Microsoft Office Shared MUI (English) 2013 v.15.0.4420.1017

Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall
2015-03-23 20:02:46Z
  Google Drive v.1.20.8672.3137
2015-03-23 20:01:01Z
  Apple Software Update v.2.1.3.127
2015-03-23 20:00:45Z
  Apple Application Support v.3.0.6
2015-03-22 15:16:03Z
  Google Update Helper v.1.3.26.9
2015-03-22 15:11:51Z
  Google Chrome v.41.0.2272.101
```
A lot of standard Microsoft Office tools but the things that stick out to me are Eraser, Google Drive, DXM_Runtime, Microsoft .NET Framework 4, and the Apple related softwares (Bonjour, Apple Software Update, Apple Application Support).

#### 12. List application execution logs. (Executable path, execution time, execution count...)
Two different artifacts come to mind when I see we need execution count: UserAssist and Prefetch. To review the Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist key I will use the regripper plugin userassist on the informant user's NTUSER.dat hive. For Prefetch I will use Eric Zimmerman's PEcmd.exe tool on the Windows\prefetch directory.
```
rip.exe -r "D:\Cases\NIST\Data Leakage Case\Kape Triage\G\Users\informant\NTUSER.DAT" -p userassist

Launching userassist v.20170204
UserAssist
Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
LastWrite Time 2015-03-22 14:35:01Z

{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA} **This GUID provides a list of applications, files, links, and other objects that have been accessed.**
2015-03-25 15:28:47Z
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\xpsrchvw.exe (1)
2015-03-25 15:24:48Z
  {6D809377-6AF0-444B-8957-A3773F02200E}\Microsoft Office\Office15\WINWORD.EXE (4)
2015-03-25 15:21:30Z
  {7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Google\Drive\googledrivesync.exe (1)
2015-03-25 15:15:50Z
  {6D809377-6AF0-444B-8957-A3773F02200E}\CCleaner\CCleaner64.exe (1)
2015-03-25 15:12:28Z
  {6D809377-6AF0-444B-8957-A3773F02200E}\Eraser\Eraser.exe (1)
2015-03-25 14:57:56Z
  C:\Users\informant\Desktop\Download\ccsetup504.exe (1)
2015-03-25 14:50:14Z
  C:\Users\informant\Desktop\Download\Eraser 6.2.0.2962.exe (1)
2015-03-25 14:46:05Z
  Microsoft.InternetExplorer.Default (5)
2015-03-25 14:42:47Z
  Microsoft.Windows.MediaPlayer32 (1)
2015-03-25 14:41:03Z
  {6D809377-6AF0-444B-8957-A3773F02200E}\Microsoft Office\Office15\OUTLOOK.EXE (5)
2015-03-24 21:05:38Z
  Chrome (7)
2015-03-24 18:31:55Z
  Microsoft.Windows.StickyNotes (13)
2015-03-24 14:16:37Z
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\rundll32.exe (1)
2015-03-23 20:27:33Z
  {6D809377-6AF0-444B-8957-A3773F02200E}\Microsoft Office\Office15\POWERPNT.EXE (2)
2015-03-23 20:26:50Z
  {6D809377-6AF0-444B-8957-A3773F02200E}\Microsoft Office\Office15\EXCEL.EXE (1)
2015-03-23 20:10:19Z
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe (4)
2015-03-22 15:24:47Z
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\slui.exe (3)
2015-03-22 15:12:32Z
  C:\Users\informant\Desktop\Download\IE11-Windows6.1-x64-en-us.exe (1)
2015-03-22 14:33:13Z
  Microsoft.Windows.GettingStarted (14)
  Microsoft.Windows.MediaCenter (13)
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\calc.exe (12)
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\SnippingTool.exe (10)
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\mspaint.exe (9)
  Microsoft.Windows.RemoteDesktop (8)
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\magnify.exe (7)
  {6D809377-6AF0-444B-8957-A3773F02200E}\Microsoft Games\Solitaire\solitaire.exe (6)

Value names with no time stamps:
  UEME_CTLCUACount:ctor
  Microsoft.Windows.ControlPanel
  {F38BF404-1D43-42F2-9305-67DE0B28FC23}\explorer.exe
  Microsoft.Windows.Shell.RunDialog
  {7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\GUMBAD6.tmp\GoogleUpdate.exe
  {7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Google\Update\GoogleUpdate.exe
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\wscript.exe
  Microsoft.Office.OUTLOOK.EXE.15
  Microsoft.Windows.ControlPanel.Taskbar
  {6D809377-6AF0-444B-8957-A3773F02200E}\Microsoft Office\Office15\FIRSTRUN.EXE
  C:\Users\informant\Downloads\icloudsetup.exe
  Microsoft.Windows.WindowsInstaller
  {7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\GUMA94B.tmp\GoogleUpdate.exe
  {7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\Common Files\Apple\Internet Services\iCloud.exe
  {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\taskmgr.exe
  Microsoft.Windows.PhotoViewer
  C:\Users\informant\AppData\Local\Temp\eraserInstallBootstrapper\dotNetFx40_Full_setup.exe
  C:\Users\informant\AppData\Local\Temp\~nsu.tmp\Au_.exe

{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F} **This GUID proivdes a list of the shortcut links used to start programs.**
2015-03-25 15:21:30Z
  {0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Google Drive\Google Drive.lnk (1)
2015-03-25 15:15:50Z
  C:\Users\Public\Desktop\CCleaner.lnk (1)
2015-03-25 15:12:28Z
  C:\Users\Public\Desktop\Eraser.lnk (1)
2015-03-25 14:46:05Z
  {9E3995AB-1F9C-4F13-B827-48B24B6C7174}\TaskBar\Internet Explorer.lnk (5)
2015-03-25 14:42:47Z
  {9E3995AB-1F9C-4F13-B827-48B24B6C7174}\TaskBar\Windows Media Player.lnk (1)
2015-03-25 14:41:03Z
  {0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Microsoft Office 2013\Outlook 2013.lnk (5)
2015-03-24 21:05:38Z
  {9E3995AB-1F9C-4F13-B827-48B24B6C7174}\TaskBar\Google Chrome.lnk (5)
2015-03-24 18:32:15Z
  {0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Microsoft Office 2013\Word 2013.lnk (1)
2015-03-24 18:31:55Z
  {0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Accessories\Sticky Notes.lnk (13)
2015-03-24 18:29:07Z
  ::{ED228FDF-9EA8-4870-83B1-96B02CFE0D52}\{00D8862B-6453-4957-A821-3D98D74C76BE} (7) **GUID maps to Solitaire.exe**
2015-03-23 17:26:50Z
  C:\Users\Public\Desktop\Google Chrome.lnk (2)
2015-03-22 14:33:13Z
  {0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Accessories\Welcome Center.lnk (14)
  {0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Media Center.lnk (13)
  {0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Accessories\Calculator.lnk (12)
  {0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Accessories\Snipping Tool.lnk (10)
  {0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Accessories\Paint.lnk (9)
  {0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Accessories\Remote Desktop Connection.lnk (8)
  {A77F5D77-2E2B-44C3-A6A2-ABA601054A51}\Accessories\Accessibility\Magnify.lnk (7)

---------------------------------------------------------------------------------------------------------------------------------------------------------------
Prefetch Parse

PECmd.exe -d "D:\Kape Triage\G\Windows\prefetch" --csv . 

| ExecutableName                | RunCount | LastRun         |
|-------------------------------|----------|-----------------|
| XPSRCHVW.EXE                  | 1        | 3/25/2015 15:28 |
| SEARCHFILTERHOST.EXE          | 82       | 3/25/2015 15:28 |
| SEARCHPROTOCOLHOST.EXE        | 76       | 3/25/2015 15:28 |
| DLLHOST.EXE                   | 59       | 3/25/2015 15:28 |
| DLLHOST.EXE                   | 7        | 3/25/2015 15:24 |
| OSPPSVC.EXE                   | 12       | 3/25/2015 15:24 |
| WINWORD.EXE                   | 3        | 3/25/2015 15:24 |
| IEXPLORE.EXE                  | 14       | 3/25/2015 15:22 |
| IEXPLORE.EXE                  | 2        | 3/25/2015 15:22 |
| GOOGLEDRIVESYNC.EXE           | 2        | 3/25/2015 15:21 |
| MSIEXEC.EXE                   | 7        | 3/25/2015 15:19 |
| MSIEXEC.EXE                   | 7        | 3/25/2015 15:18 |
| SCHTASKS.EXE                  | 2        | 3/25/2015 15:18 |
| CONHOST.EXE                   | 16       | 3/25/2015 15:18 |
| DLLHOST.EXE                   | 33       | 3/25/2015 15:18 |
| CONSENT.EXE                   | 22       | 3/25/2015 15:18 |
| AU_.EXE                       | 1        | 3/25/2015 15:18 |
| DLLHOST.EXE                   | 1        | 3/25/2015 15:18 |
| UNINST.EXE                    | 1        | 3/25/2015 15:18 |
| DLLHOST.EXE                   | 14       | 3/25/2015 15:18 |
| GOOGLEUPDATE.EXE              | 38       | 3/25/2015 15:16 |
| TASKENG.EXE                   | 25       | 3/25/2015 15:16 |
| WMIPRVSE.EXE                  | 23       | 3/25/2015 15:15 |
| CCLEANER64.EXE                | 2        | 3/25/2015 15:15 |
| AUDIODG.EXE                   | 31       | 3/25/2015 15:14 |
| ERASER.EXE                    | 2        | 3/25/2015 15:13 |
| TASKHOST.EXE                  | 7        | 3/25/2015 15:08 |
| PING.EXE                      | 1        | 3/25/2015 14:58 |
| CCSETUP504.EXE                | 1        | 3/25/2015 14:57 |
| SVCHOST.EXE                   | 6        | 3/25/2015 14:57 |
| VSSVC.EXE                     | 6        | 3/25/2015 14:57 |
| SETUPUTILITY.EXE              | 3        | 3/25/2015 14:54 |
| LODCTR.EXE                    | 7        | 3/25/2015 14:54 |
| LODCTR.EXE                    | 7        | 3/25/2015 14:54 |
| NGEN.EXE                      | 4        | 3/25/2015 14:54 |
| MSCORSVW.EXE                  | 8        | 3/25/2015 14:54 |
| NGEN.EXE                      | 4        | 3/25/2015 14:54 |
| MOFCOMP.EXE                   | 3        | 3/25/2015 14:54 |
| ASPNET_REGIIS.EXE             | 1        | 3/25/2015 14:54 |
| MOFCOMP.EXE                   | 3        | 3/25/2015 14:54 |
| ASPNET_REGIIS.EXE             | 1        | 3/25/2015 14:54 |
| WEVTUTIL.EXE                  | 4        | 3/25/2015 14:54 |
| WEVTUTIL.EXE                  | 2        | 3/25/2015 14:54 |
| SERVICEMODELREG.EXE           | 1        | 3/25/2015 14:54 |
| SC.EXE                        | 8        | 3/25/2015 14:54 |
| SERVICEMODELREG.EXE           | 1        | 3/25/2015 14:54 |
| UNLODCTR.EXE                  | 7        | 3/25/2015 14:54 |
| UNLODCTR.EXE                  | 7        | 3/25/2015 14:54 |
| MSCORSVW.EXE                  | 14       | 3/25/2015 14:53 |
| REGTLIBV12.EXE                | 7        | 3/25/2015 14:51 |
| REGTLIBV12.EXE                | 7        | 3/25/2015 14:51 |
| TMP5B99.TMP.EXE               | 1        | 3/25/2015 14:50 |
| WUAUCLT.EXE                   | 1        | 3/25/2015 14:50 |
| TMPFF8D.TMP.EXE               | 1        | 3/25/2015 14:50 |
| TRUSTEDINSTALLER.EXE          | 4        | 3/25/2015 14:50 |
| WUSA.EXE                      | 1        | 3/25/2015 14:50 |
| SETUP.EXE                     | 1        | 3/25/2015 14:50 |
| DOTNETFX40_FULL_SETUP.EXE     | 1        | 3/25/2015 14:50 |
| ERASER 6.2.0.2962.EXE         | 1        | 3/25/2015 14:50 |
| LOGONUI.EXE                   | 2        | 3/25/2015 14:45 |
| SETUP_WM.EXE                  | 1        | 3/25/2015 14:42 |
| WMPLAYER.EXE                  | 1        | 3/25/2015 14:42 |
| OUTLOOK.EXE                   | 1        | 3/25/2015 14:41 |
| SVCHOST.EXE                   | 2        | 3/25/2015 14:31 |
| MOBSYNC.EXE                   | 1        | 3/25/2015 14:19 |
| WMPNSCFG.EXE                  | 20       | 3/25/2015 14:19 |
| DLLHOST.EXE                   | 1        | 3/25/2015 13:29 |
| RUNDLL32.EXE                  | 1        | 3/25/2015 13:29 |
| CONTROL.EXE                   | 1        | 3/25/2015 13:29 |
| RUNDLL32.EXE                  | 1        | 3/25/2015 13:23 |
| WERMGR.EXE                    | 5        | 3/25/2015 13:19 |
| WSQMCONS.EXE                  | 1        | 3/25/2015 13:14 |
| WMIADAP.EXE                   | 11       | 3/25/2015 13:09 |
| SVCHOST.EXE                   | 2        | 3/25/2015 13:07 |
| SPPSVC.EXE                    | 2        | 3/25/2015 13:07 |
| MSOSYNC.EXE                   | 1        | 3/25/2015 13:07 |
| MCBUILDER.EXE                 | 1        | 3/25/2015 10:33 |
| MSCORSVW.EXE                  | 4        | 3/25/2015 10:18 |
| MSCORSVW.EXE                  | 3        | 3/25/2015 10:18 |
| CLRGC.EXE                     | 3        | 3/25/2015 10:18 |
| NETSH.EXE                     | 2        | 3/25/2015 10:18 |
| BFSVC.EXE                     | 2        | 3/25/2015 10:18 |
| DRVINST.EXE                   | 14       | 3/25/2015 10:18 |
| SEARCHINDEXER.EXE             | 1        | 3/25/2015 10:17 |
| SVCHOST.EXE                   | 1        | 3/25/2015 10:17 |
| CHROME.EXE                    | 71       | 3/24/2015 21:05 |
| RUNDLL32.EXE                  | 1        | 3/24/2015 21:03 |
| DEVICEDISPLAYOBJECTPROVIDER.E | 1        | 3/24/2015 21:02 |
| DLLHOST.EXE                   | 3        | 3/24/2015 21:01 |
| SVCHOST.EXE                   | 1        | 3/24/2015 20:58 |
| RUNDLL32.EXE                  | 1        | 3/24/2015 20:52 |
| DLLHOST.EXE                   | 3        | 3/24/2015 20:24 |
| STIKYNOT.EXE                  | 2        | 3/24/2015 18:31 |
| SOLITAIRE.EXE                 | 1        | 3/24/2015 18:29 |
| NTOSBOOT                      | 2        | 3/22/2015 14:51 |
```
#### 13. List all traces about the system on/off and the user logon/logoff. (It should be considered only during a time range between 09:00 and 18:00 in the timezone from Question 4.)

```
| EventRecordId | TimeCreated   | EventId | Computer     | MapDescription            | UserName                       | PayloadData1                         | PayloadData2 | PayloadData3      |
|---------------|---------------|---------|--------------|---------------------------|--------------------------------|--------------------------------------|--------------|-------------------|
| 62            | 3/25/15 10:33 | 4624    | informant-PC | Successful logon          | -\-                            | Target: NT AUTHORITY\ANONYMOUS LOGON | LogonType 3  | LogonId: 0x28C63  |
| 1150          | 3/25/15 13:05 | 4624    | informant-PC | Successful logon          | -\-                            | Target: NT AUTHORITY\ANONYMOUS LOGON | LogonType 3  | LogonId: 0x1C0D1  |
| 1152          | 3/25/15 13:06 | 4624    | informant-PC | Successful logon          | WORKGROUP\INFORMANT-PC$        | Target: informant-PC\informant       | LogonType 2  | LogonId: 0x25465  |
| 1153          | 3/25/15 13:06 | 4624    | informant-PC | Successful logon          | WORKGROUP\INFORMANT-PC$        | Target: informant-PC\informant       | LogonType 2  | LogonId: 0x25493  |
| 1166          | 3/25/15 14:45 | 4624    | informant-PC | Successful logon          | WORKGROUP\INFORMANT-PC$        | Target: informant-PC\informant       | LogonType 7  | LogonId: 0x157773 |
| 1170          | 3/25/15 14:45 | 4634    | informant-PC | An account was logged off |                                | Target: informant-PC\informant       | LogonType 7  | LogonId: 0x157773 |
| 1167          | 3/25/15 14:45 | 4624    | informant-PC | Successful logon          | WORKGROUP\INFORMANT-PC$        | Target: informant-PC\informant       | LogonType 7  | LogonId: 0x15777F |
| 1169          | 3/25/15 14:45 | 4634    | informant-PC | An account was logged off |                                | Target: informant-PC\informant       | LogonType 7  | LogonId: 0x15777F |
| 1191          | 3/25/15 15:30 | 4647    | informant-PC | User initiated logoff     | Target: informant-PC\informant |                                      |              | LogonId: 0x25493  |
```
```
| EventRecordId | TimeCreated      | EventId | Level | Provider                       | Channel | Computer     | UserId                                         | MapDescription                    |
|---------------|------------------|---------|-------|--------------------------------|---------|--------------|------------------------------------------------|-----------------------------------|
| 520           | 3/25/15 10:33 AM | 6005    | Info  | EventLog                       | System  | informant-PC |                                                | The Event log service was started |
| 531           | 3/25/15 10:18 AM | 109     | Info  | Microsoft-Windows-Kernel-Power | System  | informant-PC |                                                |                                   |
| 1463          | 3/25/15 1:05 PM  | 6005    | Info  | EventLog                       | System  | informant-PC |                                                | The Event log service was started |
| 1609          | 3/25/15 3:30 PM  | 1074    | Info  | USER32                         | System  | informant-PC | S-1-5-21-2425377081-3129163575-2985601102-1000 | A user initiated a system restart |
| 1610          | 3/25/15 3:30 PM  | 1074    | Info  | USER32                         | System  | informant-PC | S-1-5-21-2425377081-3129163575-2985601102-1000 | A user initiated a system restart |
| 1624          | 3/25/15 3:31 PM  | 6006    | Info  | EventLog                       | System  | informant-PC |                                                | The Event log service was stopped |
```

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

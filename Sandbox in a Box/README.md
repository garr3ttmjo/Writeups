# Sandbox in a Box

**Date:** August 3, 2024

**Author:** Garrett Jones

Challenge provided at https://github.com/jeFF0Falltrades/Tutorials/tree/master/master0Fnone_classes/2_Sandbox_in_a_Box

**Concepts:** Malware Analysis, FLARE, REMNUX

# Scenario
Malware anlysis practice with malicious executable crackme.exe provided by jeFF0Falltrades.

# Static Analysis

Start off with some static analysis.

```
file crackme.exe 
crackme.exe: PE32+ executable (GUI) x86-64, for MS Windows
```
We have a 64 bit Windows executable.
```
exiftool crackme.exe 
ExifTool Version Number         : 12.76
File Name                       : crackme.exe
Directory                       : .
File Size                       : 5.1 MB
File Modification Date/Time     : 2024:07:08 15:50:10-04:00
File Access Date/Time           : 2024:08:03 22:42:10-04:00
File Inode Change Date/Time     : 2024:08:03 22:41:35-04:00
File Permissions                : -rwxrwxrwx
File Type                       : Win64 EXE
File Type Extension             : exe
MIME Type                       : application/octet-stream
Machine Type                    : AMD AMD64
Time Stamp                      : 0000:00:00 00:00:00
Image File Characteristics      : Executable, Large address aware
PE Type                         : PE32+
Linker Version                  : 3.0
Code Size                       : 2339328
Initialized Data Size           : 221696
Uninitialized Data Size         : 0
Entry Point                     : 0x6d440
OS Version                      : 6.1
Image Version                   : 1.0
Subsystem Version               : 6.1
Subsystem                       : Windows GUI
```
Likely created on a Windows 7 system on July 8th.

```
yara-rules crackme.exe

DebuggerException__SetConsoleCtrl crackme.exe
ThreadControl__Context crackme.exe
SEH__vectored crackme.exe
network_udp_sock crackme.exe
network_tcp_listen crackme.exe
network_tcp_socket crackme.exe
network_dns crackme.exe
escalate_priv crackme.exe
win_registry crackme.exe
win_token crackme.exe
win_files_operation crackme.exe
Str_Win32_Winsock2_Library crackme.exe
Big_Numbers1 crackme.exe
Big_Numbers3 crackme.exe
CRC32_poly_Constant crackme.exe
MD5_Constants crackme.exe
RIPEMD160_Constants crackme.exe
SHA1_Constants crackme.exe
SHA512_Constants crackme.exe
SHA2_BLAKE2_IVs crackme.exe
RijnDael_AES crackme.exe
RijnDael_AES_CHAR crackme.exe
BASE64_table crackme.exe
Chacha_256_constant crackme.exe
ecc_order crackme.exe
PoetRat_Python crackme.exe
IsPE64 crackme.exe
IsWindowsGUI crackme.exe
```
Yara identified some signatures like network connections and potential PoetRat_Python behavior.

This doesn't identify too much right now but once we start our dynamic analysis we can come back to review at the executables signatures and behavior to know what to look for.

# Dynamic Analysis

Now to set up for dynamic analysis. 

My setup is a main FlareVM with a RemnuxVM running inetsim and burpsuite to act as the fake Internet. On the FlareVM I will be running Wireshark, CMDWatcher, ProcessSpawnControl, procmon, and SystemInformer to monitor the behavior of the executable. Big thanks to jeFF0Falltrades for his video showing how to set this all up!

Execute the malware and click through the CMD Watcher and Process Spawn Control prompts to allow the executable to operate.

Procmon shows a lot of activity so we need to filter it down. First filter by the crackme.exe process and analyzing the output a few things stick out.
*WriteFile operation to DACookbook.txt
*Failed attempt to access Filezilla.xml
*Failed attempt to access C:\Windows\system32\bc3be7ced1b81a73f3ef44cdbfbd5768421bbbb1c3ee5c06b8f0046c00734a9aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
*TCP connections

The DACookbook.txt is not present in the folder after the executable finishes so we can use the capture-py.py tool and point it at the directory to capture any file changes. For the TCP connections we can review our inetsim logs to analyze the traffic.

# Questions

## 1. What string, starting with the prefix "flag_", is found when running crackme.exe? (include "flag_" when entering your answer)

A tool we can use to view a process strings in memory is System Informer. Right click on the process you are investigating then choose properties, Memory, Options, Strings, then choose you minimum string length and areas of memory you want to search.

I suspended the process to give me the chance to search, then filtered for the flag_ string and it was the top result.

![image](https://github.com/user-attachments/assets/7445d852-2449-4c71-9994-c33770d76a03)


## 2. What is the full path of the file that crackme.exe attempts to access? (This *is* case-sensitive and is NOT the same file it *writes* to disk)

This we identified in during our procmon analysis, Filezilla.xml. This file is not found in the normal operations of an executable. Filezilla is a FTP (File Transfer Protocol) application and Filezilla.xml contains configuration settings for the application. This malware was likely checking the xml file to retrieve some information like user, server name, etc.

## 3. crackme.exe uses a suspicious library...how big is this DLL in bytes? (this is the file *size* NOT the *size on disk* - just type the number of bytes, not the word "bytes")

I could not identify the suspicious dll in the procmon output so we are going to pivot to another tool, pe-sieve. This tools scans a process and will identify and dump malicious injections. The tool is a simple as pointing it at the suspicious process.

```
pe-sieve /pid 368

PID: 368
Output filter: no filter: dump everything (default)
Dump mode: autodetect (default)
[*] Using raw process!
[*] Scanning: C:\Users\Sandbox\Desktop\crackme.exe
[*] Scanning: C:\Windows\System32\ntdll.dll
[*] Scanning: C:\Windows\System32\kernel32.dll
[*] Scanning: C:\Windows\System32\KERNELBASE.dll
[*] Scanning: C:\Windows\System32\bcryptprimitives.dll
[*] Scanning: C:\Windows\System32\winmm.dll
[*] Scanning: C:\Windows\System32\msvcrt.dll
[*] Scanning: C:\Windows\System32\ws2_32.dll
[*] Scanning: C:\Windows\System32\rpcrt4.dll
[*] Scanning: C:\Windows\System32\powrprof.dll
[*] Scanning: C:\Windows\System32\ucrtbase.dll
[*] Scanning: C:\Windows\System32\umpdc.dll
[*] Scanning: C:\Windows\System32\IPHLPAPI.DLL
[*] Scanning: C:\Windows\System32\nsi.dll
[*] Scanning: C:\Windows\System32\dhcpcsvc6.DLL
[*] Scanning: C:\Windows\System32\dhcpcsvc.dll
[*] Scanning: C:\Windows\System32\dnsapi.dll
[*] Scanning: C:\Windows\System32\mswsock.dll
[*] Scanning: C:\Windows\System32\rasadhlp.dll
[*] Scanning: C:\Windows\System32\FWPUCLNT.DLL
[*] Scanning: C:\Windows\System32\bcrypt.dll
[*] Scanning: C:\Windows\System32\crypt32.dll
[*] Scanning: C:\Windows\System32\msasn1.dll
[*] Scanning: C:\Windows\System32\cryptsp.dll
[*] Scanning: C:\Windows\System32\rsaenh.dll
[*] Scanning: C:\Windows\System32\CRYPTBASE.dll
[*] Scanning: C:\Windows\System32\sechost.dll
[*] Scanning: C:\Windows\System32\gpapi.dll
Scanning workingset: 206 memory regions.
[*] Workingset scanned in 125 ms.
[+] Report dumped to: process_368
[*] Dumped module to: C:\Users\Sandbox\Desktop\\process_368\165302c0000.dll as UNMAPPED
[+] Dumped modified to: process_368
[+] Report dumped to: process_368
---
PID: 368
---
SUMMARY:

Total scanned:      28
Skipped:            0
-
Hooked:             0
Replaced:           0
Hdrs Modified:      0
IAT Hooks:          0
Implanted:          1
Implanted PE:       1
Implanted shc:      0
Unreachable files:  0
Other:              0
-
Total suspicious:   1
---
```

We see it identified 1 suspicious implated PE. We can view the output dumped to the desktop. Open a cmd prompt in the folder and run dir against the dll dump to get the byte size of the file.

## 4. Speaking of that suspicious library, what is the file name opened by this library called? (just the file name, not the full path)

We can use a tool similar to strings called floss to see what may be retrieved from the dll dump. In the output we can identify a suspicious txt file.

![image](https://github.com/user-attachments/assets/50817e97-8bb6-4713-9e11-b9dbcc4cc319)

## 5. What is the full URL crackme.exe attempts to contact?

Reviewing the inetsim logs we can see a POST request was sent to a valtay.corp domain. (I removed the full url to maintain the challenge.)

```
2024-08-04 18:45:24  HTTPS connection, method: POST, URL: https://valtay.corp/, file name: /var/lib/inetsim/http/postdata/c9f40aab5edfdfb5993c2977aefe48707672d3a99a8aaf1448ef9c6afdeeb77a
```

## 6. What is the data sent to this URL? (including spaces and punctuation)

To view this we can just check the file content from the POST request, /var/lib/inetsim/http/postdata/c9f40aab5edfdfb5993c2977aefe48707672d3a99a8aaf1448ef9c6afdeeb77a.

![image](https://github.com/user-attachments/assets/f5779b7f-72f6-4989-a829-eccdf55584a7)

## 7. What is the name of the file crackme.exe writes to disk? (just the name, not the path; case sensitive)

We identified this during our procmon analysis, filter by the crackme.exe process, then check for write operations.

C:\Users\Sandbox\AppData\Roaming\txt

## 8. What are the contents of this file?

This file isn't persisted after the process finishes so point the tool capture-py.py at the folder to capture the txt file and its contents. You may have to download the Watchdog package to use this tool.
```
python capture-py.py C:\Users\Sandbox\AppData\Roaming\ . 
```

![image](https://github.com/user-attachments/assets/b1493ee2-6078-4517-8648-665c6bac7800)


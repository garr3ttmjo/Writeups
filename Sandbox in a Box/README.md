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
peframe crackme.exe 

--------------------------------------------------------------------------------
File Information (time: 0:00:08.876099)
--------------------------------------------------------------------------------
filename         crackme.exe
filetype         PE32+ executable (GUI) x86-64, for MS Windows
filesize         5103616
hash sha256      bb203ab338be9968ba5ecbdf1b53633eb15d9be82b7bc32d4e4ade86b3467788
virustotal       /
imagebase        0x400000
entrypoint       0x6d440
imphash          c2d457ad8ac36fc9f18d45bffcd450c2
datetime         1970-01-01 00:00:00
dll              False
directories      import, tls, relocations
sections         .rdata, .data, .pdata, .xdata, .idata, .reloc, .symtab, .text *
features         mutex, crypto


--------------------------------------------------------------------------------
Yara Plugins
--------------------------------------------------------------------------------
Big Numbers1
Big Numbers3
CRC32 poly Constant
MD5 Constants
RIPEMD160 Constants
SHA1 Constants
SHA512 Constants
RijnDael AES
RijnDael AES CHAR
RijnDael AES LONG
BASE64 table
IsPE64
IsWindowsGUI


--------------------------------------------------------------------------------
Behavior
--------------------------------------------------------------------------------
DebuggerException  SetConsoleCtrl
ThreadControl  Context
SEH  vectored
Xor
network udp sock
network tcp listen
network tcp socket
network dns
escalate priv
win registry
win token
win files operation

--------------------------------------------------------------------------------
Ip Address
--------------------------------------------------------------------------------
72.5.4.82
1.2.2.1
1.2.1.1
2.5.4.62
3.3.3.3
1.1.1.1
1.1.2.1
5.4.112.5
1.1.3.1
4.52.5.4
5.4.32.5
2.5.4.102

--------------------------------------------------------------------------------
Url
--------------------------------------------------------------------------------
http://chunkedCreatedIM

-------------------------------------------------------------------------------
File
--------------------------------------------------------------------------------
*syscall.DLL     Library
math.Log         Log
type:.eq.syscall.DLL Library
kernel32.dll     Library
```
This identifies possible suspicious behavior along with some IP addresses, a url, and some .dll the exe interacts with.
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
Yara identified some signatures like network connections and some PoetRat_Python behavior.

This doesn't identify too much right now but once we start our dynamic analysis we can come back to review at the executables signatures and behavior to know what to look for.

# Dynamic Analysis

Now to set up for dynamic analysis. 

My setup is a main FlareVM with a RemnuxVM running inetsim and burpsuite to act as the fake Internet. On the FlareVM I will be running Wireshark, CMDWatcher, ProcessSpawnControl, procmon, and SystemInformer to monitor the behavior of the executable. Big thanks to jeFF0Falltrades for his video showing how to set this all up!

Execute the malware and click through the CMD Watcher and Process Spawn Control prompts to allow the executable to operate.

Procmon shows a lot of activity so we need to filter it down. First filter by the crackme.exe process and analyzing the output a few things stick out.
*WriteFile operation to C:\Users\Sandbox\AppData\Roaming\DACookbook.txt
*TCP connections that should be picked up by inetsim
*Suspcious dll at C:\Users\Sandbox\Desktop\CRYPTBASE.dll


# Questions

## 1. What string, starting with the prefix "flag_", is found when running crackme.exe? (include "flag_" when entering your answer)

## 2. What is the full path of the file that crackme.exe attempts to access? (This *is* case-sensitive and is NOT the same file it *writes* to disk)

## 3. crackme.exe uses a suspicious library...how big is this DLL in bytes? (this is the file *size* NOT the *size on disk* - just type the number of bytes, not the word "bytes")

## 4. Speaking of that suspicious library, what is the file name opened by this library called? (just the file name, not the full path)

## 5. What is the full URL crackme.exe attempts to contact?

## 6. What is the data sent to this URL? (including spaces and punctuation)

## 7. What is the name of the file crackme.exe writes to disk? (just the name, not the path; case sensitive)

## 8. What are the contents of this file?

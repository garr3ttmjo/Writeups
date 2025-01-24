# ChatGPT Forensics - Windows Desktop App

**Date:** January 23, 2025

**Author:** Garrett Jones

Challenge provided by David Cowen at https://www.hecfblog.com/2025/01/daily-blog-723-sunday-funday-11925.html

## Challenge
Determine how to extract chat history out of the Chat GPT desktop app and what other data you can extract that would useful in an investigation (user name, login times, etc..)

## Analysis

The Windows ChatGPT app is still in demo so you will need to download from the Microsoft Store.

I couldn't find information on where the ChatGPT app stores its user files and ChatGPT says no user history is stored locally.

<img width="758" alt="image" src="https://github.com/user-attachments/assets/dd6e0dc4-9fa3-4b4f-b5c2-a6d1fde11e0c" />

Next, I used ProcessMonitor to get an idea of what files the app is interacting with when you enter your queries. Filter by ProcessName is ChatGPT.exe and Operation contains Write to get the files the app is writing data to.

<img width="1438" alt="image" src="https://github.com/user-attachments/assets/e1c20c20-c264-4382-a36a-31d4ed9fc040" />

This reveals a base user directory.

**Path:**
``` C:\Users\<user>\AppData\Local\Packages\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\LocalCache\Roaming\ChatGPT ```

<img width="545" alt="image" src="https://github.com/user-attachments/assets/2547f7b9-f102-4324-b136-30f19f6e69e7" />

### Chat History

Query history can be found in the IndexedDB/https_chatgpt.com_0.indexeddb.leveldb directory. It contains the structure of a LevelDB database but right now the data is collecting in the .log file.

**Path:**
```C:\Users\<user>\AppData\Local\Packages\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\LocalCache\Roaming\ChatGPT\IndexedDB\https_chatgpt.com_0.indexeddb.leveldb```

<img width="639" alt="image" src="https://github.com/user-attachments/assets/8373b595-8b86-4839-9721-8adbbaf3de44" />

Running strings on the .log file with give you the question and response history. See red for question and yellow for the response.

![image](https://github.com/user-attachments/assets/a0e14bd6-44f8-44cd-8483-5d76e14cb3ac)

### Session Data

Session data can be found in the Local Storage\leveldb directory inside leveldb files.

**Path:**
```C:\Users\<user>\AppData\Local\Packages\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\LocalCache\Roaming\ChatGPT\Local Storage\leveldb```

Using ldbdump against the .ldb files can provide start times tied to a session ID.

**Install:**
```go install github.com/golang/leveldb/cmd/ldbdump@latest```


```
& "C:\Users\Garrett\go\bin\ldbdump.exe" 000021.ldb | Select-String -Pattern "sessionID"

"_https://chatgpt.com\x00\x01statsig.session_id.1876492556\x012\x01\x00\x00\x00\x00\x00": "\x01{\"sessionID\":\"c30be97
2-0feb-44ef-86ec-bfb9246d9bd7\",\"startTime\":1737535465842,\"lastUpdate\":1737537628585}",
"_https://chatgpt.com\x00\x01statsig.session_id.1876492556\x01.\x01\x00\x00\x00\x00\x00": "\x01{\"sessionID\":\"c30be97
2-0feb-44ef-86ec-bfb9246d9bd7\",\"startTime\":1737535465842,\"lastUpdate\":1737536645805}",
"_https://chatgpt.com\x00\x01statsig.session_id.1876492556\x01,\x01\x00\x00\x00\x00\x00": "\x01{\"sessionID\":\"c30be97
2-0feb-44ef-86ec-bfb9246d9bd7\",\"startTime\":1737535465842,\"lastUpdate\":1737536625789}",
"_https://chatgpt.com\x00\x01statsig.session_id.1876492556\x01*\x01\x00\x00\x00\x00\x00": "\x01{\"sessionID\":\"c30be97
2-0feb-44ef-86ec-bfb9246d9bd7\",\"startTime\":1737535465842,\"lastUpdate\":1737536615799}",
"_https://chatgpt.com\x00\x01statsig.session_id.1876492556\x01(\x01\x00\x00\x00\x00\x00": "\x01{\"sessionID\":\"c30be97
2-0feb-44ef-86ec-bfb9246d9bd7\",\"startTime\":1737535465842,\"lastUpdate\":1737536605803}",
"_https://chatgpt.com\x00\x01statsig.session_id.1876492556\x01%\x01\x00\x00\x00\x00\x00": "\x01{\"sessionID\":\"c30be97
2-0feb-44ef-86ec-bfb9246d9bd7\",\"startTime\":1737535465842,\"lastUpdate\":1737536595795}",
"_https://chatgpt.com\x00\x01statsig.session_id.1876492556\x01!\x01\x00\x00\x00\x00\x00": "\x01{\"sessionID\":\"c30be97
2-0feb-44ef-86ec-bfb9246d9bd7\",\"startTime\":1737535465842,\"lastUpdate\":1737536585794}",
"_https://chatgpt.com\x00\x01statsig.session_id.2179354269\x013\x01\x00\x00\x00\x00\x00": "\x01{\"sessionID\":\"fa9ee99
5-c691-431a-b51d-79da8f6e76cb\",\"startTime\":1737535465812,\"lastUpdate\":1737537628608}",
"_https://chatgpt.com\x00\x01statsig.session_id.2179354269\x01&\x01\x00\x00\x00\x00\x00": "\x01{\"sessionID\":\"fa9ee99
5-c691-431a-b51d-79da8f6e76cb\",\"startTime\":1737535465812,\"lastUpdate\":1737536595702}",
"_https://chatgpt.com\x00\x01statsig.session_id.2179354269\x01\"\x01\x00\x00\x00\x00\x00": "\x01{\"sessionID\":\"fa9ee9
95-c691-431a-b51d-79da8f6e76cb\",\"startTime\":1737535465812,\"lastUpdate\":1737536585703}",
```
Convert the Unix date times to a readable format
```
date -r $((1737535465812 / 1000))
Wed Jan 22 02:44:25 CST 2025

date -r $((1737536585703 / 1000))
Wed Jan 22 03:03:05 CST 2025
```
The most recent session shows:
* Session ID: fa9ee995-c691-431a-b51d-79da8f6e76cb
* Start Time: Wed Jan 22 02:44:25 CST 2025
* Last Update Time: Wed Jan 22 03:03:05 CST 2025















# ChatGPT Forensics - Windows Desktop App

**Date:** January 23, 2025

**Author:** Garrett Jones

Topic provided by David Cowen at https://www.hecfblog.com/2025/01/daily-blog-723-sunday-funday-11925.html

## Challenge
Determine how to extract chat history out of the Chat GPT desktop app and what other data you can extract that would useful in an investigation (user name, login times, etc..)

## Writeup

The Windows ChatGPT app is still in demo so you will need to download from the Microsoft Store.

I couldn't find information where the ChatGPT app stores its user files and when I asked ChatGPT it said no user history was stored locally.

<img width="758" alt="image" src="https://github.com/user-attachments/assets/dd6e0dc4-9fa3-4b4f-b5c2-a6d1fde11e0c" />

Next, I used ProcessMonitor to get an idea of what files the app is interacting with when you enter your queries. Filter by ProcessName is ChatGPT.exe and Operation contains Write to get the files the app is writing data to.

<img width="1438" alt="image" src="https://github.com/user-attachments/assets/e1c20c20-c264-4382-a36a-31d4ed9fc040" />

This reveals a base user directory of 

``` C:\Users\<user>\AppData\Local\Packages\OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0\LocalCache\Roaming\ChatGPT ```

Below are the contents of this directory.

<img width="545" alt="image" src="https://github.com/user-attachments/assets/2547f7b9-f102-4324-b136-30f19f6e69e7" />


Query history can be found in the IndexedDB/https_chatgpt.com_0.indexeddb.leveldb directory. It contains the structure of a LevelDB database but all the data seems to collect in the .log file.

<img width="639" alt="image" src="https://github.com/user-attachments/assets/8373b595-8b86-4839-9721-8adbbaf3de44" />

Running strings on the .log file with give you the question and response history. See red for question and yellow for the response.

![image](https://github.com/user-attachments/assets/a0e14bd6-44f8-44cd-8483-5d76e14cb3ac)













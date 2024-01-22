#The Hacking Case
Date: January 21, 2024
Author: Garrett Jones

Challenge provided by NIST at https://cfreds.nist.gov/all/NIST/HackingCase.
Questions can be found at https://cfreds-archive.nist.gov/Hacking_Case.html.

#Scenario
On 09/20/04 , a Dell CPi notebook computer, serial # VLQLW, was found abandoned along with a wireless PCMCIA card and an external homemade 802.11b antennae. It is suspected that this computer was used for hacking purposes, 
although cannot be tied to a hacking suspect, G=r=e=g S=c=h=a=r=d=t. (The equal signs are just to prevent web crawlers from indexing this name; there are no equal signs in the image files.)  
Schardt also goes by the online nickname of “Mr. Evil” and some of his associates have said that he would park his vehicle within range of Wireless Access Points 
(like Starbucks and other T-Mobile Hotspots) where he would then intercept internet traffic, attempting to get credit card numbers, usernames & passwords.
Find any hacking software, evidence of their use, and any data that might have been generated. Attempt to tie the computer to the suspect, G=r=e=g S=c=h=a=r=d=t.
A DD image (in seven parts: 1, 2, 3, 4, 5, 6, 7, 8, and notes) and a EnCase image (second part) of the abandoned computer have already been made.

To examine this case I will be using Autopsy, EZ-Tools by Eric Zimmerman, and some other miscellaneous tools. To start off we will create our case in Autopsy and select our image source. I am choosing to use the Encase image and then running the default ingest modules to see what it finds.

#Questions
1. What is the image hash? Does the acquisition and verification hash match?
	First action in an investigation should be to ensure you haven't altered or corrupted your image in any way so you know data integrity remains. The way to do this is by matching the hashes of the files. Below shows a html report from the acquisition of the images containing MD5 hashes.

	![1](https://github.com/garr3ttmjo/Writeups/assets/108881417/56c918f1-5456-4ff1-8d16-053d6e8a76f0)
	
	We can then use the certUtil -hashfile function to hash the images in our environment to make sure they are the same.
	
	![2](https://github.com/garr3ttmjo/Writeups/assets/108881417/cfe5e730-3c83-4eb2-a8fd-bcc7531f097f)
	
	Autopsy also will take a hash of the data source image but it is processing the E01 and E02 files together so its hash will be different. You can view this by right clicking on your data source then selecting view summary information and going to the container tab.
	
	![3 pmg](https://github.com/garr3ttmjo/Writeups/assets/108881417/4748cd86-caf4-4ef7-a865-73eb0acc44bd)
	
	
3. What operating system was used on the computer?
	This is information Autopsy will pull for you when you the default modules and you can view it under the Data Artifacts/Operating System tab.
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/4f30f75a-02cf-43ab-bbfd-24b973e4830c)


	But I actually prefer to check this kind of information manually because its decently simple, good practice, and can often times give more information than Autopsy provides. Autopsy pulls this information from a registry key so we can just use a tool like Eric Zimmerman's Registry Explorer to view it as well. First we need to extract the registry hives we want to parse from the image. I am going to extract these hives using Autopsy but another good method is to mount the image using Arsenal Image Mounter and then use Kape and run KapeTriage and it will collect a multitude of valuable artifacts for you. But for our method we can first move to the Windows/System32/config folder and select the DEFAULT, SAM, software, SECURITY, and system hives and extract them to your selected folder. Then we can drag and drop these hives into Registry Explorer. The operating system information is going to be in the software hive under the Microsoft\Windows NT\CurrentVersion key. Navigate here and in the value view box to the right we will see the information we are looking for.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/e876dc6b-66b0-4dcf-97c2-9c46cbeee63f)

	The answer to our question is under ProductName which tells us the operating system is Microsoft Windows XP.

4. When was the install date?
	The operating system install date is under the same registry key Microsoft\Windows NT\CurrentVersion but as you can see in the InstallDate entry 1092955707 is not data we can get any value from. Lots of data isn't stored in Ascii or readable text to us so we have to right click on the data entry and select data interpreter to figure out what the actual date time is in something we can read. This displays a few different options so you may need to google to figure out which of the dates applies to this value. 
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/cd1f689a-bce3-4675-9dbc-c508e3ec26a5)

	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/eefe251b-cb97-4c4b-bdce-693d736d41d1)

	So our install date is 2004-08-19 22:48:27.
	
5. What is the timezone settings?
	This is another piece of information we will find in the registry but instead under the system hive. This registry key is system\ControlSet001\Control\TimeZoneInformation. 
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/2c40d895-b23d-4f52-b147-17310cdd0bf0)


	Here we can see the system timezone is Central Standard Time.
	
6. Who is the registered owner?
	Registered owner is under the CurrentVersion information along with the operating system info.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/a699e77f-0896-4f93-b148-d65ad17e087b)

	
	Under RegisteredOwner we can see a name, Greg Schardt.
	
7. What is the computer account name?
	Computer account name is found under registry key System\ControlSet001\Control\ComputerName\ComputerName.

	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/42158569-6f17-4b7b-8456-68fff13803da)

	Computer account name: N-1A9ODN6ZXK4LQ
	
8. What is the primary domain name?
	After some research I found that the default domain name is stored in the software\Microsoft\Windows NT\CurrentVersion\Winlogon key.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/e3effee6-0f2a-42c0-aba0-7d3a74ff9acc)

	And you can see that the DomainName is the same as our computer name from the previous question. The answer key shows the answer to be Mr. Evil so maybe there was a mix up with the ValueNames. But here we have Domain Name is "Dr. Evil".
	
9. When was the last recorded computer shutdown date/time?
	The last shutdown can be found under System\ControlSet001\Control\Windows\ShutdownTime key. But for some reason I am not able to find anything in this location under either control set. So I am going to try another registry tool called RegRipper and run it against the system hive using the shutdown plugin.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/b78c7615-4723-4c2b-86ee-8e2524d1f158)

	This gives us the last ShutdownTime being 2004-08-27 15:46:33Z.
	
10. How many accounts are recorded (total number)?
	This answer can be found in the SAM (Security Account Manager) hive under the SAM\SAM\Domains\Account\Users\Names key and gives us a good view of the 5 accounts.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/15a67655-2ebd-4d16-8d80-cead5088578c)

	This can also be viewed in Autopsy under the OS Accounts tab.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/0a06016a-b252-4265-ae5e-fbc42ce895b3)

11. What is the account name of the user who mostly uses the computer?
	To do analysis on user activity we are going to move to user specific artifacts of the UsrClass.dat and NTUSER.dat files which provide user account specific information. Good places to see activity within these files are Shellbags and MRUs. Shellbags are how Window stores a users window viewing preferences through Windows Explorer but also happens to be a good forensic artifact for recently visited locations. RecentDocs MRU gives us a view of some of the Most Recently Used (MRU) files and folders visited by the user. RecentDocs MRU is found at NTUSER.dat\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs and Shellbags can be found at NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags but is hard to parse in registry explorer so better way is to analyze using EZ-Tools Shell Bag Explorer. If you explore the users NTUSER.dat hives you will see that Mr. Evil is the account with the most activity.
	
	Mr. Evil RecentDocs
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/50539928-218d-4f11-9d9f-fc6c36e4f488)

	
	Mr. Evil Shellbags Summary

	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/a57e249e-b4a1-45d1-92ed-8adcb0a4b2c4)

	Autopsy will also collect this information for you under the Recent Documents and Shell Bags tabs in Data Artifacts.
	
	Shell Bags

 	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/7367cd4d-f814-4219-bef8-5ce257a4cfcf)

	RecentDocs
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/2915f449-96bc-48a2-81ac-69356325fb3a)

13. Who was the last user to logon to the computer?
	The answer to this question can be found in the SAM hive at SAM\SAM\Domain\Account\Users but the view in Registry Explorer is not the best so I am going to export the User Accounts table as a csv and view it in another EZ-Tool called Timeline Explorer which is used to view csv files. I drag and drop the exported file and format a little to find the answer. As we can see Mr. Evil was actually the only user to ever log in and the Last Login Time was 2004-08-27 15:08:23.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/a9077ed9-09ff-4df9-9da7-bca9b445c0bc)

	I believe normally Autopsy should grab this information for you but for some reason it isn't provided under the OS Accounts tab. It only has created time and not last login time.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/95581a5c-c8ec-4be6-851f-cf608b54ea70)

14. A search for the name of “G=r=e=g S=c=h=a=r=d=t” reveals multiple hits. One of these proves that G=r=e=g S=c=h=a=r=d=t is Mr. Evil and is also the administrator of this computer. What file is it? What software program does this file relate to?
	For a string search Autopsy is probably the best bet. In the top right corner there is a Keyword Search option which you click and type in "Greg Schardt" and then click search. It will bring up around 10 files as a result. 

 	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/ddc8a2ba-c0da-40a5-8e95-e41b299e34c7)

	Now you will want to go through each of these files and see if there is any information connecting Mr. Evil to Greg Schardt. In the irunin.ini file we find something interesting.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/d22dcc29-ea04-442e-b0ec-7261ce4f4e7f)

	We can see that the Registered Owner is Greg Schardt and the programs he is using are under the Mr. Evil account. This file is apart of the Look@LAN program under Program Files.
	
	AppEvent.Evt also ties Greg Schardt and Mr. Evil together.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/c076c3de-c016-41ab-8fa5-28d477c9bcde)

15.  List the network cards used by this computer
	This can be found under the software\Microsoft\Windows NT\CurrentVersion\NetworkCards key and we see two entries.
	
 	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/4da4ea6d-b6f2-4edc-a621-43fc7b8d61d5)

   	____________________________________________________________________________________________________

	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/8e383028-6d3d-4ef1-aeca-01bb73755b18)

16. This same file reports the IP address and MAC address of the computer. What are they?
	This questions sounds like we were supposed to find this information another way so lets look around the Look@Lan program we found earlier because that is network related. Back in the irunin.ini we find this.
	
 	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/4d92b56b-4f04-4924-8349-c115ec9def9e)

	NIC stands for Network Interface Card and gives us the MAC Address and right above it is its IP. So we have an IP of 192.168.1.111 and a MAC address of 0010a4933e09.
	
17. An internet search for vendor name/model of NIC cards by MAC address can be used to find out which network interface was used. In the above answer, the first 3 hex characters of the MAC address report the vendor of the card. Which NIC card was used during the installation and set-up for LOOK@LAN?
	Googling the MAC address tells you it’s a Xircom device and looking at question 13 we can see it corresponds to the Xircom Ethernet Interface.

 	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/abefd599-95ae-44ec-8c66-0fffd5718b42)

18. Find 6 installed programs that may be used for hacking.
	The best way to do this is to go through the Program Files and google anything you don't know that might relate to hacking.

 	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/bab90f7f-b56f-4b42-b542-f7fd86ccbbdb)

	• Anonymizer - An anonymizer or an anonymous proxy is a tool that attempts to make activity on the Internet untraceable. It is a proxy server computer that acts as an intermediary and privacy shield between a client computer and the rest of the Internet.

	• Cain and Abel - a password recovery tool for Microsoft Windows. It could recover many kinds of passwords using methods such as network packet sniffing, cracking various password hashes by using methods

	• Ethereal - this is the predecessor to Wireshark which is a free and open-source packet analyzer that can be used for network sniffing.

	• Network Stumbler - tool for Windows that facilitates detection of Wireless LANs using the 802.11b, 802.11a and 802.11g WLAN standards.

	• WinPcap - For many years, WinPcap has been recognized as the industry-standard tool for link-layer network access in Windows environments, allowing applications to capture and transmit network packets bypassing the protocol stack, and including kernel-level packet filtering, a network statistics engine and support for remote packet capture.

	• Whois - Whois performs the registration record for the domain name or IP address that you specify.

	• 123WASP - 123 Write All Stored Passwords (WASP) will display all passwords of the currently logged on user that are stored in the Microsoft PWL file.

20. What is the SMTP email address for Mr. Evil?
	During my research on the programs in the Program Files folder I saw that Agent was referring to some kind of mail agent so that sounds like a good place to start. Going through the files nothing stands out until the Data folder where you start to see "Mr Evil <whoknowsme@sbcglobal.net>" in some if the IDX files. This is suspicious but lets keep looking. Keep going down the list and you will end up at the AGENT.INI file which specifies configurations for the program. Here we find the exact info we were looking for.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/962691b7-75b8-4171-b20b-b1ae00d67e8e)

	A useful tool Autopsy has is Keywords Lists where you can do a search for data string types like email, phone numbers, IP addresses, and more. This method could have pointed you in the right direction.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/ec16cd14-5bf1-4521-90c2-fd68eb1ff055)

	I also did a string search for @ in registry explorer and it found this in the Mr. Evils NTUSER.dat file. You could then look this up in Autopsy to find more information.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/ac34d1a7-75d0-48d0-a4eb-82f95a8945ee)

21. What are the NNTP (news server) settings for Mr. Evil?
	I found this server news.dallas.sbcglobal.net doing a string search for "news" in registry explorer. This searching for it in Autopsy brought me back to the AGENT.INI file.

 	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/8e637810-54de-4fb6-b75d-42039d20305f)

22. What two installed programs show this information?
	The first progam is the one we have been looking at AGENT which after more research is short for Forte Agent (Forté Agent is an email and Usenet news client used on the Windows operating system.)
	
	The string search for "news" on registry explorer within Mr. Evil's NTUSER.DAT file brings up Outlook Express as a news software.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/0b72aa00-e795-4cf5-90a8-1af22e32c99e)

	But I have not be able to find any reference to the new.dallas.sbcglobal.net server in any of the Outlook Express file it does have a NNTP registry key at \Microsoft\Outlook Express\Outlook NewsReader\Protocols\nntp meaning this program does use nntp.
23. List 5 newsgroups that Mr. Evil has subscribed to?
	Trying to find more information on the news server I decided to do a substring match instead of a keyword search to see if that brought up any different results. Along with the 4 results that came up earlier now it found a lot of dbx files. Looking up .dbx extension tells you it’s a type of email file and scrolling through the text you will see these are news emails that the user subscribed to.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/c3a170a0-e2f1-40f0-99c0-8b401f7d3090)

	So to select 5 we can say
		○ Alt.2600.cardz
		○ Alt.2600.codez
		○ Alt.2600.crackz
		○ Alt.binaries.hacking.beginner
		○ Alt.binaries.hacking.computers
24. A popular IRC (Internet Relay Chat) program called MIRC was installed.  What are the user settings that was shown when the user was online and in a chat channel?
	Going into the mIRC program folder and looking at the files we see a mirc.ini file which likely has the setting for the program. Here we find a user, email, and nickname.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/820419e7-6c5a-48c9-bc65-ddb1c6d3cf07)

	Then we can go into the log files and see him participating in some chat rooms.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/d1992045-6dc0-4732-84a7-a9616696e12c)

25. This IRC program has the capability to log chat sessions. List 3 IRC channels that the user of this computer accessed.
	These are the chat rooms found in the logs folder.

 	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/31f08785-11f7-41b5-bf71-0f93719ec7bd)

26. Ethereal, a popular “sniffing” program that can be used to intercept wired and wireless internet packets was also found to be installed. When TCP packets are collected and re-assembled, the default save directory is that users \My Documents directory. What is the name of the file that contains the intercepted data?
	This default save directory hint is misleading because if you check Mr. Evil's My Document folder there is nothing there but if you go back to the Mr. Evil folder you will find a file called "interception". When you check the metadata of the file you will see it’s a .pcap extension or packet capture and is the normal output of a network sniffer.

 	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/2b967b63-1def-4854-b43a-62ff9d2d0326)

27. Viewing the file in a text format reveals much information about who and what was intercepted. What type of wireless computer was the victim (person who had his internet surfing recorded) using?
	Viewing the text of the file will reveal the answer right away. UA stands for User Agent and OS is operating system. This reveals the UA computer to be a Windows CE (Pocket PC).
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/66967280-4d2a-4ce7-a649-50cea2e36121)

	And probably looked something like this.

 	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/8ced317c-5e4b-4490-9548-c431fff4762a)

	https://phonedb.net/index.php?m=device&id=77&c=psion_teklogix_netbook_pro&d=image
	
28. What websites was the victim accessing?
	Continue scrolling through the file and you see the UA is using Firefox reach out to a host at mobile.msn.com to get to MSN Hotmail.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/7ade4f65-5146-45e5-b65d-7d05ebb90b5e)

29. Search for the main users web based email address. What is it?
	This question asks for a web based email address so its not going to be one of the local agents we had looked at earlier. A good place to start are the web artifacts Autopsy collects for you including the Web Bookmarks, Web Cookies, Web History, and Web Search. Bookmarks and web search don't seem to have anything and cookies has some things that stick out like mr. evil@yahoo.txt but that isn't an email address. That leaves web history contained in the index.dat files. Scrolling through and looking at the domains yahoo is the one that really sticks out to me but its still hard to manually look through all the text. So I do a substring search for "@yahoo.com" and then sort by name to find the index.dat files and there are only 2 with @yahoo addresses.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/1b883db8-921b-411c-8be3-cc0bc4525ae3)

30. Yahoo mail, a popular web based email service, saves copies of the email under what file name?
	Now that we have his yahoo email we can assume any saved emails will have his address in them so we can do a substring search for it and look through the results.

	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/029b1933-89dc-44d3-a3aa-07ce7f961098)
	These appear to be downloaded emails and have the .htm extension which stands for html.
	
31. How many executable files are in the recycle bin?
	Using Autopsy to navigate inside the RECYCLER folder we will see there are 4 executables.

 	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/dd89eff7-430a-4f40-9a7b-ae374f62d4f1)

	I wanted to see if the might be anything else hiding here so I mounted the E01 image with Arsenal Image Mounter and ran KAPE recycling bin plugins.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/99e2d387-77d3-43af-8131-0516c682130b)

	But it found the same files as Autopsy.
	
32. Are these files really deleted?
	These files are not deleted because they still have allocated space and are easily recoverable as shown by the allocated flags. This is different from files that might need to be carved to be recovered.

 	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/5c7e9fcf-9599-43d6-9cc7-e306d1f89383)

33. How many files are actually reported to be deleted by the file system?
	Autopsy's analysis has this number at 365.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/fe2a3edb-de7d-46fa-b60c-b4f001c508e9)

34. Perform a Anti-Virus check. Are there any viruses on the computer?

	Ran a ClamAV scan against the drive I mounted this image to.

 	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/b3a7c1ba-5c98-432a-ac16-4942f50410de)

	ClamAV didn't find any infected files. On the other hand, Autopsy found something and put it under their "Interesting Items" tab as a possible zip bomb.
	
	![image](https://github.com/garr3ttmjo/Writeups/assets/108881417/74c9a431-dbc8-4b8d-8557-8673d58dbab1)

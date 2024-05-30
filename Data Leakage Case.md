Questions

1. What are the hash values (MD5 & SHA-1) of all images?
1. Does the acquisition and verification hash value match?
1. Identify the partition information of PC image.
1. Explain installed OS information in detail. (OS name, install date, registered owner…)
1. What is the timezone setting?
1. What is the computer name?
1. List all accounts in OS except the system accounts: Administrator, Guest, systemprofile, LocalService, NetworkService. (Account name, login count, last logon date…)
1. Who was the last user to logon into PC?
1. When was the last recorded shutdown date/time?
1. Explain the information of network interface(s) with an IP address assigned by DHCP.
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

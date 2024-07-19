# 

**Date:** January 21, 2024

**Author:** Garrett Jones

Challenge provided by NIST at https://cfreds.nist.gov/all/NIST/HackingCase.

Questions can be found at https://cfreds-archive.nist.gov/Hacking_Case.html.

**Concepts:** Windows Disk Forensics, Registry Analysis, Autopsy, EZ-Tools

# Scenario
On 09/20/04 , a Dell CPi notebook computer, serial # VLQLW, was found abandoned along with a wireless PCMCIA card and an external homemade 802.11b antennae. It is suspected that this computer was used for hacking purposes, 
although cannot be tied to a hacking suspect, G=r=e=g S=c=h=a=r=d=t. (The equal signs are just to prevent web crawlers from indexing this name; there are no equal signs in the image files.)  
Schardt also goes by the online nickname of “Mr. Evil” and some of his associates have said that he would park his vehicle within range of Wireless Access Points 
(like Starbucks and other T-Mobile Hotspots) where he would then intercept internet traffic, attempting to get credit card numbers, usernames & passwords.

Find any hacking software, evidence of their use, and any data that might have been generated. Attempt to tie the computer to the suspect, G=r=e=g S=c=h=a=r=d=t.

A DD image (in seven parts: 1, 2, 3, 4, 5, 6, 7, 8, and notes) and a EnCase image (second part) of the abandoned computer have already been made.

To examine this case I will be using Autopsy, EZ-Tools by Eric Zimmerman, and some other miscellaneous tools. To start off we will create our case in Autopsy and select our image source. I am choosing to use the Encase image and then running the default ingest modules to see what it finds.

# Questions
#### 1. What is the image hash? Does the acquisition and verification hash match?

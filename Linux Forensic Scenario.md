# Linux Forensics Scenario

**Date:** January 29th, 2024

**Author:** Garrett Jones

Challenge created by Jean Carlos Martins Miguel and can be found at:
 * https://cfreds.nist.gov/all/utfpr/LinuxForensicsScenario
 * https://drive.google.com/drive/folders/1_C-YorlEjuiCF6dBPmKhLd2Z7l43Q9YN
 
## Scenario
On May 3, 2007, the Federal Police, in an operation against the distribution of child pornography seized a computer in a residence on Zero street in São Paulo. The computer was seized and the computer owner confessed to the police that he has illicit files related to sexual abuse and exploitation and that he sells this content. So, you were hired to work with the police as a Forensics Analyst, now you have to help them to find as much evidence as you can that will be used as proof  in court to send the criminal to jail.

**Note:** Obviously it is just a machine in order to people study, developing and learn computer forensics , so there is no child sexual abuse and exploitation images, so for the purpose of this scenario/challenge we created the story above, and the images that will be considered illegal are just pistache photos taken from a machine learning dataset.

## Investigation and Questions




#### What’s the name of a hidden folder? and where is it? Is it a suspicious folder? How many files did you find inside this folder?
To look for a hidden folder I am going to navigate to the home/ubuntuforensics folder and run "ls -ld .?*" to find all hidden items in the directory.
This brings up the normal hidden folders but some new ones as well. The one that sticks out the most is ".for sales_copy" directory. We can cd into
this to view the contents. I see these are pistachio pictures and will now run "ls -1 | wc -l" to count the number of files in the directory. The count is 833.

#### Write the name of suspicious files you’ve found and the path where they are located! Hint: Do not forget that a skilled professional would look anywhere and any kind of file such as audios,text files,videos, etc.Here will be considered as suspicious files just .txt files.
This involves exploring the system to find files that contain information important to the base.
	
	* /home/ubuntuforensics/Documents/clients/clients_email
	* /home/ubuntuforensics/Documents/byName/for_clients.txt
	
These provide information on clients potentially involved in bad activities.


#### How many deleted images were you able to recover? Both images that are in the recycle bin and images deleted from the recycle bin (Just pistaches pictures are considered as suspicious).

#### Did you find any suspicious “zip” file which can be a possible proof? What is or are the name of these files and the password ?
There are various zip files but two stick out because FTK Imager doesn't allow me to see the images inside which likely means they are password protected.
The zip files are _.zip and #.zip located in the /Downloads/Images directory. I'll extract them and then run 7z from the command line with the password I found
from cracking the Private.key in the question below but you could do the same process but with zip2john or fcrackzip. Here I have the password so can run 7z like "7z -p"root" e \#.zip"
and get the pistachio images.

#### Were you able to identify any kind of steganography? If yes, what kind of information did you extract from the suspicious file? How many files could you find that were applied steganography? And how are they called?
Just triaging around the system I came across the Documents/special client directory where the images didn't seem to match up with the others I'd seen. 
So I extracted all of the images to a separate folder and ran this bash line to loop through the images and see if anything could be extracted using the password we have found "root". 
The code is "for image in *.jpg; do steghide extract -sf "$image" -p root && echo "File found in: $image" || echo "No file found in: $image"; done" and Steghide extracts 5 pistachio images from the unsplash jpgs.
	
#### There are browsers  installed so maybe the criminal used it as  a tool to do some kind of illicit search on the Internet. Could you find any kind of url or anything related to suspicious searches? Here we considered as suspicious searches every website that contains the following string: F0r3ns1cs
I found evidence of two browsers on the system, Firefox and Tor. Tor is used for its anonymity so it is unlikely we will find useful information there but still worth a try.
For both browsers I will locate the places.sqlite files which can be found under a profile in each browser directory. Then you can use a tool like DB Browser for SQLite to view the database files.
Within the database the table we want to view is the moz_places table. Tor's moz_places didn't reveal any valuable url information but it did have content meaning it was used. Firefox's moz_places
did reveal the information we were looking for. There is a google search for for3ns1cs and f0r3ns1cs and then a visit to the url https://compactor.bandcamp.com/album/d1g1tal-f0r3ns1cs. This is the
suspicious search history we wanted. There were also searches for police departments and computer crime which is also suspicious in a child exploitation case.

##### The police have a database of file hashes that have already been seized, whether from illegal sites or illegally distributed content, so if they find a match to those hash it means that those files were found on sites that practiced criminal/illegal activities.So your goal is to find the files that have the following hashes (SHA1 hash function):

	* f1010ce85f3bac86c564403f454db46332f2937e  
	* a9ce3a402bd06756afa6caa6cd985381cf544ed7  
	* 2144749eaea65bf7bc8d40a071eab444a382ee1d  
	* ea7595007b7b9d8482fd3cc3d06035802bf79287 

I am sure there are tools out there that can do a scan of all the files on the system and match them to these hashes but I couldn't find one to do it simply.
Instead I had happened to view the .bash_history file which stores recent bash commands the user ran and saw they used the "sha1sum" command on 4 images. 
Now we can just need to find these images and hash them to see if the values are the same.

Manually looking through the folders  I found Fig1848.jpg in the Downloads/Images/Images directory has a hash of ea7595007b7b9d8482fd3cc3d06035802bf79287 and matches the 4th hash value on the list but the file name is different so there must be another place to look.
Kept looking and found the Downloads/Images Backup/Images folder which contains the 4 files we are looking for. I ran this bash code to get the hashes of the 4 files "for file in Figure216.jpg Figure233.jpg Figure235.jpg Figure1848.jpg; do sha1sum "$file"; done".
And the output matches the files we were looking for.

                                                                                            
#### There are encrypted files which can be used as proof, were you able to find them? Could you crack them? Did you find any cryptographic key? Write the name of these  files. Hint: If you find the private key you can crack the files easily.
Upon my original triage of the system and ubuntuforensics directory I found a Private.key file used for a PGP encryption. Then later on within the "Pics_to_clients" directory you find GPG encrypted jpegs.
GPG is an implementation of the PGP encryption so we might try using this Private key to crack the encryption.

The tool I am going to use for this is John the Ripper on my windows machine. First we have to convert the private key into a hash John can read. 
To do this we can run "C:\Tools\john-1.9.0-jumbo-1-win64\run\gpg2john.exe" "D:\Linux Forensics\Suspicious Artifacts\Private.key > gpghash.txt". So we have the necessary hash to be cracked and now we can run John on it.
I downloaded 10-million-password-list-top-1000000.txt as my password word list and then ran "C:\Tools\john-1.9.0-jumbo-1-win64\run\john.exe" --wordlist="10-million-password-list-top-1000000.txt" "D:\Linux Forensics\Suspicious Artifacts\gpghash.txt"
This successfully cracked the hash and gave the password used to create the private key. 

Now I am going to go to my Linux system and run "apt-get install gnupg" to get the gpg software and then run 
gpg --import -o /mnt/d/Linux\ Forensics/Suspicious\ Artifacts/Private.key to import the private key to my wallet. Then I can navigate to the "Pics_to_clients" directory I can run this bash code 
"for i in *.gpg; do if [ -e "$i" ]; then gpg -d -o "$(echo "$i" | sed 's/\.gpg$//')" "$i"; fi; done" to loop through encrypted files and decrypt them. Run this and I only have to type the password once and it outputs the decrypted files.

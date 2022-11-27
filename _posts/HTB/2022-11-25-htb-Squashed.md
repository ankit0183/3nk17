---
title: Squashead - Hack The Box
excerpt: "Squashed is an Easy Difficulty Linux machine that features a combination of both identifying and leveraging
misconfigurations in NFS shares through impersonating users. Additionally, the box incorporates the"
date: 2022-11-25 
categories:
  - hackthebox
tags:  
  - osticket
  - mysql
  - mattermost
  - hashcat
  - rules
image: /assets/img/htb/squashed/info.png
---


Squashed is an Easy Difficulty Linux machine that features a combination of both identifying and leveraging
misconfigurations in `NFS shares` through impersonating users. Additionally, the box incorporates the
enumeration of an `X11 display` into the `privilege escalation` by having the attacker take a screenshot of the
current Desktop.

# Enumaration


## Port Scan

```php

nmap -sC -sV 10.10.11.191
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-27 11:12 IST
Nmap scan report for 10.10.11.191
Host is up (0.13s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Built Better
|_http-server-header: Apache/2.4.41 (Ubuntu)
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      45669/tcp6  mountd
|   100005  1,2,3      50287/udp6  mountd
|   100005  1,2,3      53317/tcp   mountd
|   100005  1,2,3      54473/udp   mountd
|   100021  1,3,4      33785/tcp6  nlockmgr
|   100021  1,3,4      34763/tcp   nlockmgr
|   100021  1,3,4      39022/udp   nlockmgr
|   100021  1,3,4      50677/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.97 seconds
```
The nmap scan shows a standard SSH service running on `port 22` , an Apache webserver running on port
`80` , as well as NFS and rpcbind running on their default ports

![](/assets/img/htb/squashed/4.png)


## Enumerating NFS

NFS is a `server/client`  system enabling users to share files and directories across a network and allowing
those shares to be `mounted locally`. While both useful and versatile, `NFS` has no protocol for `authorization`
or authentication, making it a common pitfall for misconfiguration and therefore exploitation.
We begin our enumeration by listing any potentially available shares hosted on the `target machine`.

>showmount -e squashed.htb

### Port 22

No anon login allowed so let’s move on.

### Port 80

several html pages with nothing interesting. `No subdirs`, `no subdomains`.

![](/assets/img/htb/squashed/1.png)

we see the how Beutifull Website developer made

```php
$ showmont -e 10.10.11.191

Export list for 10.10.11.191

/home/ross *

/var/www/html *
```


Since we already saw whats in `/html` let’s dig into `home` folder first

>>sudo mount -t nfs 10.129.228.109:/home/ross


>~/Documents/htb/squashed -o nolock

```php
└─$ dir -lah
total 68K
drwxr-xr-x 14 ftpuser ftpgroup 4.0K Nov 19 09:21 .
drwxr-xr-x 33 kali kali 4.0K Nov 19 09:20 ..
lrwxrwxrwx 1 root root 9 Oct 20 09:24 .bash_history -> /dev/null
drwx - - - 11 ftpuser ftpgroup 4.0K Oct 21 10:57 .cache
drwx - - - 12 ftpuser ftpgroup 4.0K Oct 21 10:57 .config
drwxr-xr-x 2 ftpuser ftpgroup 4.0K Oct 21 10:57 Desktop
drwxr-xr-x 2 ftpuser ftpgroup 4.0K Oct 21 10:57 Documents
drwxr-xr-x 2 ftpuser ftpgroup 4.0K Oct 21 10:57 Downloads
drwx - - - 3 ftpuser ftpgroup 4.0K Oct 21 10:57 .gnupg
drwx - - - 3 ftpuser ftpgroup 4.0K Oct 21 10:57 .local
drwxr-xr-x 2 ftpuser ftpgroup 4.0K Oct 21 10:57 Music
drwxr-xr-x 2 ftpuser ftpgroup 4.0K Oct 21 10:57 Pictures
drwxr-xr-x 2 ftpuser ftpgroup 4.0K Oct 21 10:57 Public
drwxr-xr-x 2 ftpuser ftpgroup 4.0K Oct 21 10:57 Templates
drwxr-xr-x 2 ftpuser ftpgroup 4.0K Oct 21 10:57 Videos
lrwxrwxrwx 1 root root 9 Oct 21 09:07 .viminfo -> /dev/null
-rw - - - - 1 ftpuser ftpgroup 57 Nov 19 09:21 .Xauthority
-rw - - - - 1 ftpuser ftpgroup 2.5K Nov 19 09:21 .xsession-errors
-rw - - - - 1 ftpuser ftpgroup 2.5K Oct 31 06:13 .xsession-errors.old
```

Documents contains a `Passwords.kdbx`, a keepass password database



When listing the contents of `/var/www/html` , which is now mounted at /mnt/1 , it becomes evident that
while we can see filenames, we cannot see the files' owners or `permissions`. That also means we cannot
read the files' contents or modify them whatsoever. We can, however, check the actual directory's
permissions by running ls on the folder itself.


```yaml
ls -ld /mnt/1
```

We can see that the directory is owned by the `UID 2017`, and belongs to the group with the ID of `www-data` ,
or `33` . This means that on the target box, i.e the server hosting the share, the directory is owned by a user
with that specific UID. We proceed to the second share

```yaml
sudo mount -t nfs squashed.htb:/home/ross /mnt/2
```

Following the blog we exfiltrate the cookie from our mounted share to our local attackbox and reupload it so we can use it with our alex user. Remember, we want to steal the session of ross so we have to do this on the victim.

After trying xrdp for a while I checked the other xtools. [https://clearlinux.org/software/bundle/x11-tools](https://clearlinux.org/software/bundle/x11-tools)

xwd allows us to take a screenshot of the current session, this is a good start.


we found the password root  `cah$mei7rai9A`

so we can connect with ssh


![](/assets/img/htb/squashed/3.png)


![](/assets/img/htb/squashed/2.png)




<div style="width:480px"><iframe allow="fullscreen" frameBorder="0" height="480" src="https://giphy.com/embed/YB7rR6R9TzzwsCchnb/video" width="480"></iframe></div>
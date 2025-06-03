---
title: "OverTheWire: Bandit (Level 0 - 15)"
summary: "This post covers the solutions for all levels of the OverTheWire Bandit game, from Level 0 to Level 15.This is a comprehensive guide to help you navigate through the challenges and learn essential Linux commands and concepts."
description: "This post covers the solutions for all levels of the OverTheWire Bandit game, from Level 0 to Level 15. This is a comprehensive guide to help you navigate through the challenges and learn essential Linux commands and concepts."
categories: ['Linux', 'OverTheWire', 'Bandit']
tags: ['Beginner']
date: 2 June 2025
draft: false
---
# My solutions for Bandit - OverTheWire.org
## Bandit Level 0

```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
```
Connect to the server using the provided command. The password is `bandit0`.
Password for Bandit Level 1 is found in the file `readme` in the home directory of Bandit Level 0.
Password: `ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If`

## Bandit Level 1

```bash
bandit1@bandit:~$ cat /home/bandit1/-
263JGJPfgU6LtdEvgfWU1XP5yac29mFx
```
Password for Bandit Level 2 is found in the file `-` in the home directory of Bandit Level 1.
Password: `263JGJPfgU6LtdEvgfWU1XP5yac29mFx`

## Bandit Level 2

```bash
bandit2@bandit:~$ cat spaces\ in\ this\ filename 
MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx
```
Password for Bandit Level 3 is found in the file `spaces in this filename` in the home directory of Bandit Level 2.

Password: `MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx`

## Bandit Level 3

```bash
bandit3@bandit:~/inhere$ ls -la
total 12
drwxr-xr-x 2 root    root    4096 Apr 10 14:23 .
drwxr-xr-x 3 root    root    4096 Apr 10 14:23 ..
-rw-r----- 1 bandit4 bandit3   33 Apr 10 14:23 ...Hiding-From-You
bandit3@bandit:~/inhere$ cat ...Hiding-From-You 
2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ
```
Password for Bandit Level 4 is found in the file `...Hiding-From-You` in the home directory of Bandit Level 3.
Password: `2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ`

## Bandit Level 4
 We will use the file command to get the information about the files. From files command, we now know that the file07 contains ASCII text
```bash
bandit4@bandit:~/inhere$ file ./*
./-file00: PGP Secret Sub-key -
./-file01: data
./-file02: data
./-file03: data
./-file04: data
./-file05: data
./-file06: data
./-file07: ASCII text
./-file08: data
./-file09: data
bandit4@bandit:~/inhere$ cat ./-file07 
4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw
```
Password: `4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw`

## Bandit Level 5

```bash
bandit5@bandit:~/inhere$ find . -size 1033c
./maybehere07/.file2
bandit5@bandit:~/inhere$ cat ./maybehere07/.file2
HWasnPhtq9AVKe0dmk45nxy20cvUa6EG
```
Used `-size` flag to find the file with size 1033 bytes. The file is located in `maybehere07` directory
Password: `HWasnPhtq9AVKe0dmk45nxy20cvUa6EG`

## Bandit Level 6

```bash
bandit6@bandit:~$ find / -user bandit7 -group bandit6 -size 33c
/var/lib/dpkg/info/bandit7.password
bandit6@bandit:~$ cat /var/lib/dpkg/info/bandit7.password
morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj    
```
Used the `find` command to locate files owned by user `bandit7` and group `bandit6` with a size of 33 bytes, starting from the root directory. The password file was found at `/var/lib/dpkg/info/bandit7.password`.
Password: `morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj`
## Bandit Level 7

```bash
bandit7@bandit:~$ ls
data.txt
bandit7@bandit:~$ file data.txt 
data.txt: Unicode text, UTF-8 text
bandit7@bandit:~$ cat data.txt | grep "millionth"
millionth	dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc
bandit7@bandit:~$ 
```
Used the `file` command to check the type of `data.txt`, which revealed it was a Unicode text file. Then, used `grep` to search for the string "millionth" in the file, which returned the password.
Password: `dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc`

## Bandit Level 8

```bash
bandit8@bandit:~$ file data.txt 
data.txt: ASCII text
bandit8@bandit:~$ cat data.txt | sort |less
bandit8@bandit:~$ cat data.txt | sort | uniq -u
4CKMh1JI91bUIZZPXDqGanal4xvAg0JM
```
Used the `file` command to check the type of `data.txt`, which revealed it was an ASCII text file. Then, used `sort` to order the lines, and `uniq -u` to print only the unique line (the password). The `-u` option ensures only lines that appear exactly once are shown, filtering out any duplicates.
Password: `4CKMh1JI91bUIZZPXDqGanal4xvAg0JM`
## Bandit Level 9

```bash
bandit9@bandit:~$ file data.txt 
data.txt: data
bandit9@bandit:~$ cat data.txt | grep "===="
grep: (standard input): binary file matches
bandit9@bandit:~$ strings data.txt | grep "=="
========== the
========== password{k
=========== is
========== FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey
```
Used the `file` command to check the type of `data.txt`, which revealed it was a binary file. Then, used `strings` to extract printable strings from the binary file and `grep` to search for lines containing "==". This returned the password.
Password: `FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey`
## Bandit Level 10

```bash
bandit10@bandit:~$ cat data.txt 
VGhlIHBhc3N3b3JkIGlzIGR0UjE3M2ZaS2IwUlJzREZTR3NnMlJXbnBOVmozcVJyCg==
bandit10@bandit:~$ cat data.txt | base64 --decode
The password is dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr
```
Used `base64 --decode` to decode the base64 encoded string in `data.txt`, which revealed the password.
Password: `dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr`
## Bandit Level 11

```bash
bandit11@bandit:~$ cat data.txt 
Gur cnffjbeq vf 7k16JArUVv5LxVuJfsSVdbbtaHGlw9D4
```
Used an online ROT13 decoder to decode the string in `data.txt`, which revealed the password.
Password: `7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4`
## Bandit Level 12

```bash
bandit12@bandit:~$ mkdir /tmp/d3let3
bandit12@bandit:~$ cp data.txt /tmp/d3let3
bandit12@bandit:~$ cd /tmp/d3let3
bandit12@bandit:/tmp/d3let3$ ls
data.txt
bandit12@bandit:/tmp/d3let3$ xxd -r data.txt data
bandit12@bandit:/tmp/d3let3$ gzip -d data
gzip: data: unknown suffix -- ignored
bandit12@bandit:/tmp/d3let3$ mv data txt.gz
bandit12@bandit:/tmp/d3let3$ gzip -d txt.gz 
bandit12@bandit:/tmp/d3let3$ cat txt 
bandit12@bandit:/tmp/d3let3$ file txt
txt: bzip2 compressed data, block size = 900k
bandit12@bandit:/tmp/d3let3$ mv txt txxt.bz2
bandit12@bandit:/tmp/d3let3$ bzip2 -d txxt.bz2 
bandit12@bandit:/tmp/d3let3$ file txxt 
txxt: gzip compressed data, was "data4.bin", last modified: Thu Apr 10 14:22:57 2025, max compression, from Unix, original size modulo 2^32 20480
bandit12@bandit:/tmp/d3let3$ mv txxt d4ta.gz
bandit12@bandit:/tmp/d3let3$ gzip -d d4ta.gz 
bandit12@bandit:/tmp/d3let3$ file d4ta 
d4ta: POSIX tar archive (GNU)
bandit12@bandit:/tmp/d3let3$ tar -xvf d4ta
data5.bin
bandit12@bandit:/tmp/d3let3$ file data5.bin 
data5.bin: POSIX tar archive (GNU)
bandit12@bandit:/tmp/d3let3$ tar -xvf data5.bin
data6.bin
bandit12@bandit:/tmp/d3let3$ file data6.bin 
data6.bin: bzip2 compressed data, block size = 900k
bandit12@bandit:/tmp/d3let3$ mv data6.bin data6.bz
bandit12@bandit:/tmp/d3let3$ bzip -d data6.bz 
Command 'bzip' not found, but there are 21 similar ones.
bandit12@bandit:/tmp/d3let3$ bzip2 -d data6.bz 
bandit12@bandit:/tmp/d3let3$ file data6 
data6: POSIX tar archive (GNU)
bandit12@bandit:/tmp/d3let3$ tar -xvf data6
data8.bin
bandit12@bandit:/tmp/d3let3$ file data8.bin 
data8.bin: gzip compressed data, was "data9.bin", last modified: Thu Apr 10 14:22:57 2025, max compression, from Unix, original size modulo 2^32 49
bandit12@bandit:/tmp/d3let3$ mv data8.bin data8.gz
bandit12@bandit:/tmp/d3let3$ gzip -d data8.gz 
bandit12@bandit:/tmp/d3let3$ file data8
data8: ASCII text
bandit12@bandit:/tmp/d3let3$ cat data8
The password is FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn
```
Used a series of commands to decode and extract the password from the file `data.txt`. The process involved creating a temporary directory, copying the file, using `xxd` to reverse the hex dump, decompressing with `gzip`, renaming files, and finally extracting the password from the last file.
Password: `FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn`
## Bandit Level 13

```bash
bandit13@bandit:~$ ssh -i sshkey.private -p 2220 bandit14@localhost
bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS
```
Used the private SSH key `sshkey.private` to connect to Bandit Level 14. The password for Bandit Level 14 is found in the file `/etc/bandit_pass/bandit14`.
Password: `MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS`

## Bandit Level 14

```bash
bandit14@bandit:~$ nc localhost 30000
MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS
Correct!
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo

^C
bandit14@bandit:~$ 
```
Used `nc` (netcat) to connect to localhost on port 30000. The server prompts for the password, which is the same as the previous level's password. After entering the correct password, it returns the new password.
Password: `8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo`

## Bandit Level 15

```bash
bandit15@bandit:~$ openssl s_client -connect localhost:30001
CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 CN = SnakeOil
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = SnakeOil
verify return:1
---
Certificate chain
 0 s:CN = SnakeOil
   i:CN = SnakeOil
   a:PKEY: rsaEncryption, 4096 (bit); sigalg: RSA-SHA256
   v:NotBefore: Jun 10 03:59:50 2024 GMT; NotAfter: Jun  8 03:59:50 2034 GMT
---
Server certificate
-----BEGIN CERTIFICATE-----
MIIFBzCCAu+gAwIBAgIUBLz7DBxA0IfojaL/WaJzE6Sbz7cwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIU25ha2VPaWwwHhcNMjQwNjEwMDM1OTUwWhcNMzQwNjA4
MDM1OTUwWjATMREwDwYDVQQDDAhTbmFrZU9pbDCCAiIwDQYJKoZIhvcNAQEBBQAD
ggIPADCCAgoCggIBANI+P5QXm9Bj21FIPsQqbqZRb5XmSZZJYaam7EIJ16Fxedf+
jXAv4d/FVqiEM4BuSNsNMeBMx2Gq0lAfN33h+RMTjRoMb8yBsZsC063MLfXCk4p+
09gtGP7BS6Iy5XdmfY/fPHvA3JDEScdlDDmd6Lsbdwhv93Q8M6POVO9sv4HuS4t/
jEjr+NhE+Bjr/wDbyg7GL71BP1WPZpQnRE4OzoSrt5+bZVLvODWUFwinB0fLaGRk
GmI0r5EUOUd7HpYyoIQbiNlePGfPpHRKnmdXTTEZEoxeWWAaM1VhPGqfrB/Pnca+
vAJX7iBOb3kHinmfVOScsG/YAUR94wSELeY+UlEWJaELVUntrJ5HeRDiTChiVQ++
wnnjNbepaW6shopybUF3XXfhIb4NvwLWpvoKFXVtcVjlOujF0snVvpE+MRT0wacy
tHtjZs7Ao7GYxDz6H8AdBLKJW67uQon37a4MI260ADFMS+2vEAbNSFP+f6ii5mrB
18cY64ZaF6oU8bjGK7BArDx56bRc3WFyuBIGWAFHEuB948BcshXY7baf5jjzPmgz
mq1zdRthQB31MOM2ii6vuTkheAvKfFf+llH4M9SnES4NSF2hj9NnHga9V08wfhYc
x0W6qu+S8HUdVF+V23yTvUNgz4Q+UoGs4sHSDEsIBFqNvInnpUmtNgcR2L5PAgMB
AAGjUzBRMB0GA1UdDgQWBBTPo8kfze4P9EgxNuyk7+xDGFtAYzAfBgNVHSMEGDAW
gBTPo8kfze4P9EgxNuyk7+xDGFtAYzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4ICAQAKHomtmcGqyiLnhziLe97Mq2+Sul5QgYVwfx/KYOXxv2T8ZmcR
Ae9XFhZT4jsAOUDK1OXx9aZgDGJHJLNEVTe9zWv1ONFfNxEBxQgP7hhmDBWdtj6d
taqEW/Jp06X+08BtnYK9NZsvDg2YRcvOHConeMjwvEL7tQK0m+GVyQfLYg6jnrhx
egH+abucTKxabFcWSE+Vk0uJYMqcbXvB4WNKz9vj4V5Hn7/DN4xIjFko+nREw6Oa
/AUFjNnO/FPjap+d68H1LdzMH3PSs+yjGid+6Zx9FCnt9qZydW13Miqg3nDnODXw
+Z682mQFjVlGPCA5ZOQbyMKY4tNazG2n8qy2famQT3+jF8Lb6a4NGbnpeWnLMkIu
jWLWIkA9MlbdNXuajiPNVyYIK9gdoBzbfaKwoOfSsLxEqlf8rio1GGcEV5Hlz5S2
txwI0xdW9MWeGWoiLbZSbRJH4TIBFFtoBG0LoEJi0C+UPwS8CDngJB4TyrZqEld3
rH87W+Et1t/Nepoc/Eoaux9PFp5VPXP+qwQGmhir/hv7OsgBhrkYuhkjxZ8+1uk7
tUWC/XM0mpLoxsq6vVl3AJaJe1ivdA9xLytsuG4iv02Juc593HXYR8yOpow0Eq2T
U5EyeuFg5RXYwAPi7ykw1PW7zAPL4MlonEVz+QXOSx6eyhimp1VZC11SCg==
-----END CERTIFICATE-----
subject=CN = SnakeOil
issuer=CN = SnakeOil
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 2103 bytes and written 373 bytes
Verification error: self-signed certificate
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Server public key is 4096 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 18 (self-signed certificate)
---
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 68C81752B64BEF2EDBEEE104C3E43CE1A85B8CED5573A2621DF10DD4BB4E026A
    Session-ID-ctx: 
    Resumption PSK: D5EE94BABC7C01AF9FAAD92CD58927794DCB1661BD92F968F4AC11C87751F3B5DCECA5598C3828167F69241A98F23452
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - 90 26 4b 61 3e 89 95 1a-4b 9c 04 1b 5a 25 70 8d   .&Ka>...K...Z%p.
    0010 - 9b e7 47 fc b3 e2 2a fd-e2 be 05 14 24 01 28 0d   ..G...*.....$.(.
    0020 - e0 c4 33 a6 fc 30 ce d7-f1 b1 36 37 00 90 a8 26   ..3..0....67...&
    0030 - a0 8e 8a eb 20 9c 19 fb-ba 08 85 c4 b9 cc 0c e0   .... ...........
    0040 - cc a9 7b f1 1c 73 65 35-dc 97 66 20 9e d3 76 20   ..{..se5..f ..v 
    0050 - f0 29 04 21 6e c3 26 b6-10 db 1d be 9d 1d 8f b4   .).!n.&.........
    0060 - bd cd 71 03 f9 d8 4a ae-9f ff f2 66 d7 e3 26 a2   ..q...J....f..&.
    0070 - 81 8a 59 ec d4 1f 2c d7-43 63 58 cf 51 fc fe 5b   ..Y...,.CcX.Q..[
    0080 - 0e 7d 67 42 52 01 36 20-cc 18 4c 72 cc 94 91 1f   .}gBR.6 ..Lr....
    0090 - 61 d8 3b 49 6a 93 ef 43-19 61 af 74 7a 09 51 8c   a.;Ij..C.a.tz.Q.
    00a0 - 0b ea 02 b5 28 08 f1 a9-57 5a 0c 7a 96 1d a8 19   ....(...WZ.z....
    00b0 - f3 ab fc ef 25 e9 f1 99-f4 7f e4 a9 46 84 4b 76   ....%.......F.Kv
    00c0 - 3f 02 27 6e e4 a2 05 23-0f 00 ab d2 a3 46 54 b8   ?.'n...#.....FT.
    00d0 - fe 8a 5d 43 6e 4b a4 35-8b bd 3d 1d 0a 52 18 9b   ..]CnK.5..=..R..

    Start Time: 1748921757
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_256_GCM_SHA384
    Session-ID: 406F9FED595D10EB429D57EB4CC0965D24E5355FBF5859C38E29C2BCEE4B5FF7
    Session-ID-ctx: 
    Resumption PSK: E5E19083A209E4154DEED6BC5E7C82F9548222E8ADDB491A5C273FA65CE7E70A7B3EAC6D4F2AF8594B4476BB423C096F
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - 90 26 4b 61 3e 89 95 1a-4b 9c 04 1b 5a 25 70 8d   .&Ka>...K...Z%p.
    0010 - 78 23 7e 72 59 10 2d 55-07 81 d7 85 45 f5 9a c5   x#~rY.-U....E...
    0020 - ed fc e2 8c 1f 65 ce 69-c0 05 86 49 16 ac 16 64   .....e.i...I...d
    0030 - a3 bb 85 18 d3 03 e0 bc-32 39 7b 24 ec bd f4 47   ........29{$...G
    0040 - 58 9d e5 e9 83 89 84 fe-ab 22 d1 bb 3c 98 e2 03   X........"..<...
    0050 - d9 fc 2d 6c 1b 44 1c ed-c8 1f 3f 26 be 50 10 88   ..-l.D....?&.P..
    0060 - cd f0 57 3e ae 14 f0 36-10 17 6b b6 01 69 46 11   ..W>...6..k..iF.
    0070 - 9e e2 07 3a c9 a0 0e 26-29 c3 2c 65 b8 3e 81 90   ...:...&).,e.>..
    0080 - a4 18 59 65 8c c7 33 05-50 5e 09 8f 2a 12 90 c1   ..Ye..3.P^..*...
    0090 - 14 c8 39 9c ed 5f 73 dc-11 9e 7a d8 73 68 31 63   ..9.._s...z.sh1c
    00a0 - 90 68 53 b5 61 f4 bb f3-24 0d f1 4a c8 1e f8 e8   .hS.a...$..J....
    00b0 - ff 98 93 b4 ab d2 66 9a-67 b0 a5 5f 77 f5 46 44   ......f.g.._w.FD
    00c0 - d9 c1 41 15 8c 9d 1d 62-a2 5f da 1e db ed ee 31   ..A....b._.....1
    00d0 - cd 94 c8 b5 fd d7 12 16-20 d1 f5 84 bb 4f d2 f7   ........ ....O..

    Start Time: 1748921757
    Timeout   : 7200 (sec)
    Verify return code: 18 (self-signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo
Correct!
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx

closed
bandit15@bandit:~$ 
```
Used `openssl s_client` to connect to localhost on port 30001. The server presents a self-signed certificate, which is accepted despite the verification error. After entering the correct password, it returns the new password.
Password: `kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx`

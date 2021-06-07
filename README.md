# Satori-Zeek
Zeek port for Satori TCP/IP fingerprinting

How to install:

create a folder called "satori" in zeek/share/zeek/site/ and copy the .zeek files from this repository to that folder.

Add the following line to zeek.local (zeek/share/zeek/site/zeek.local)

```bash
@load ./satori
```

If you want to get the zeek logs in JSON output you will have to add the following line to zeek.local

```bash
@load policy/tuning/json-logs.zeek
```

Outputs of the script can be found in the custom log file osfp.log

The logs contain two OS-fingerprint signatures. One is for the satori DB : <br/>
https://github.com/xnih/satori/blob/master/fingerprints/tcp.xml <br/>
<br/>
The other is for the CSIRT-MU PassiveOSFingerprint DB : <br/>
https://github.com/CSIRT-MU/PassiveOSFingerprint/blob/master/fingerprint_database.csv



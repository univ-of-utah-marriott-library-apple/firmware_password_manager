#!/usr/bin/python

import subprocess

fwpw_hash_raw = subprocess.check_output(["/usr/sbin/nvram", "fwpw-hash"])
fwpw_hash_raw = fwpw_hash_raw.split('\n')[0]
fwpw_hash     = fwpw_hash_raw.split('\t')[1]
fwpw_version  = fwpw_hash.split(':')[0]

if fwpw_version == "2":
    print "<result>"+fwpw_hash+"</result>"
else:
    print "<result>Bad</result>"

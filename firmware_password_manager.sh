#!/bin/sh

################################################################################
# Copyright (c) 2014 University of Utah Student Computing Labs.
# All Rights Reserved.
#
# Permission to use, copy, modify, and distribute this software and
# its documentation for any purpose and without fee is hereby granted,
# provided that the above copyright notice appears in all copies and
# that both that copyright notice and this permission notice appear
# in supporting documentation, and that the name of The University
# of Utah not be used in advertising or publicity pertaining to
# distribution of the software without specific, written prior
# permission. This software is supplied as is without expressed or
# implied warranties of any kind.
################################################################################

################################################################################
# firmware_password_manager.sh
#
# This script uses Apple's setregproptool to automate changing the firmware
# password.
#
#
#	1.0.0	2014.08.20	Initial version. tjm
#
################################################################################

################################################################################
# things to do/test:
#
#
################################################################################

#
# The keyfile contains the current and new firmware passwords.
# It is also hashed and the value stored in nvram for future comparison.
#
# keyfile format:
#
# | #							<-- Lines beginning with hashmarks, "comments" are ignored.
# | # date of change 			<-- useful for recording dates, previous hashes, etc.
# | current:currentpasswword 	<-- the assumed current password.
# | new:newpassword 			<-- the new password to be installed.
#

#
# usage: logmessage "level" "text" "location"
# example: logmessage "CRITICAL" "setregproptool not found." "/var/log/test.log"
#
logmessage() {
	echo $(/bin/date) "$1": "$2" >> "$3"
}

#
# path to location of keyfile
#
localkeyfilename="/private/var/root/fwpw.txt"

#
# path to specific log file
#
loglocation="/var/log/management/firmware_password_manager.log"
if ! /bin/test -f "$loglocation"
then
	touch "$loglocation"
fi

#
# path to location of setregproptool
# check to make sure binary exists.
# The binary normally lives here: Firmware\ Password\ Utility.app/Contents/Resources/setregproptool
# We found it easier to move the binary out of the app to another location
#
setregproppath="/usr/local/bin/setregproptool"
if ! /bin/test -x "$setregproppath"
then
	logmessage "ERROR" "setregproptool not found." "$loglocation"
	echo $runhost $rundate "setregproptool not found." | $(/usr/bin/mail -s "Firmware Password Manager error" "$mailto")
	command /usr/bin/srm -mz "$localkeyfilename"
	exit 1
else
	logmessage "INFO" "setregproptool found." "$loglocation"
fi

#
# email alert recipients
# add addresses as appropriate
#
mailto=""

#
# additional details for email alerts
#
rundate=$(/bin/date)
runhost=$(/usr/sbin/system_profiler SPNetworkDataType | grep -m1 "IPv4 Addresses" | /usr/bin/cut -d":" -f2 | /usr/bin/cut -d" " -f2)

#
# check to see if there is a current fwpw set and store results
#
`"$setregproppath" -c`
fwpwIsSet=$?

#
# flips return from setregproptool, 0=no pw, 1=pw
# I found it more intuitive to flip the results.
#
if (/bin/test $fwpwIsSet -eq 0)
then
	fwpwIsSet=1
else
	fwpwIsSet=0
fi

#
# Check for existance of keyfile
# create hash of keyfile
#
if ! /bin/test -f "$localkeyfilename"
then
	logmessage "ERROR" "No keyfile found." "$loglocation"
	echo $runhost $rundate "No keyfile found." | $(/usr/bin/mail -s "Firmware Password Manager error" "$mailto")
	exit 1
fi
incomingHash=$(/usr/bin/openssl dgst -sha256 "$localkeyfilename" | /usr/bin/cut -d"=" -f2)

#
# check if hash present in nvram, copy for later comparison
#
if /bin/test $fwpwIsSet -eq 1
then
	currentHash=$(/usr/sbin/nvram fwpw-hash | /usr/bin/cut -f2)
fi

#
# compare hashes, exit if identical and secure delete file.
#
if (/bin/test "X$incomingHash" = "X$currentHash")
then
	logmessage "INFO" "Hashes match, no change required." "$loglocation"
	echo $runhost $rundate "Hashes match, no change required." | $(/usr/bin/mail -s "Firmware Password Manager report" "$mailto")
	command /usr/bin/srm -mz "$localkeyfilename"
	if /bin/test $? -ne 0
	then
		logmessage "ERROR" "srm reported non-0 result." "$loglocation"
		exit 1
	else
		logmessage "INFO" "srm reported success." "$loglocation"
	fi
	exit 0
fi

#
# parse keyfile, discard comments.
#
newPassword="empty"
currentPassword="empty"

while read item; do
	field="$(echo $item | /usr/bin/cut -d":" -f1)"
	subfield="$(echo $item | /usr/bin/cut -d":" -f2)"
	if (/bin/test ! "$(echo $item | /usr/bin/cut -d"#" -f1)")
	then
#		discard commented lines
		printf ""
	elif (/bin/test "X$field" = "Xnew")
	then
		newPassword=$subfield
	elif (/bin/test "X$field" = "Xcurrent")
	then
		currentPassword=$subfield
	fi
done<$localkeyfilename

#
# if variables are blank, consider this an error condition and exit
#
if /bin/test "X$newPassword" = "X"
then
	logmessage "ERROR" "Empty new password string. Bad keyfile format?" "$loglocation"
	echo $runhost $rundate "Empty new password string. Bad keyfile format?" | $(/usr/bin/mail -s "Firmware Password Manager error" "$mailto")
	command /usr/bin/srm -mz "$localkeyfilename"
	exit 1
fi

if /bin/test "X$currentPassword" = "X"
then
	logmessage "ERROR" "Empty current password string. Bad keyfile format?" "$loglocation"
	echo $runhost $rundate "Empty current password string. Bad keyfile format?" | $(/usr/bin/mail -s "Firmware Password Manager error" "$mailto")
	command /usr/bin/srm -mz "$localkeyfilename"
	exit 1
fi

#
# change password.
# no current password set.
#
if /bin/test $fwpwIsSet -eq 0
then
	logmessage "INFO" "No fw password set." "$loglocation"
	command "$setregproppath" -m "command" -p "$newPassword"
	if /bin/test $? -ne 0
	then
		logmessage "ERROR" "setregproptool reported non-0 result." "$loglocation"
		echo $runhost $rundate "setregproptool reported non-0 result." | $(/usr/bin/mail -s "Firmware Password Manager error" "$mailto")
		command /usr/bin/srm -mz "$localkeyfilename"
		exit 1
	else
		logmessage "INFO" "setregproptool reported success." "$loglocation"
	fi
#
# existing password.
#
# handle an incorrect current password situation
# setregproptool will enter an infinite loop if the current password from the keyfile
# is different from the machines fw password.
# catch this condition, kill setregproptool and exit
#
else
	logmessage "INFO" "Replacing current fw password." "$loglocation"
	badPasswd=$(/usr/bin/expect <<- DONE
		set timeout 2
		spawn "$setregproppath" -m command -p "$newPassword" -o "$currentPassword"
		expect "*nter current password:*"
	DONE)
	if [[ "$badPasswd" == *current* ]]; then
		badPID=$(ps -opid,comm -U root | grep setregproptool | cut -d" " -f1)
		command kill -9 "$badPID"
		logmessage "ERROR" "setregproptool process killed. Mismatching current password?" "$loglocation"
		echo $runhost $rundate "setregproptool process killed. Mismatching current password?" | $(/usr/bin/mail -s "Firmware Password Manager error" "$mailto")
		command /usr/bin/srm -mz "$localkeyfilename"
		exit 1
	else
		logmessage "INFO" "setregproptool reported success." "$loglocation"
	fi
fi

#
# update nvram with new hash value
#
command /usr/sbin/nvram fwpw-hash="$incomingHash"

#
# secure delete keyfile
#
command /usr/bin/srm -mz "$localkeyfilename"
if /bin/test $? -ne 0
then
	logmessage "ERROR" "srm reported non-0 result." "$loglocation"
	exit 1
else
	logmessage "INFO" "srm reported success." "$loglocation"
fi

#
# housekeeping, logging, reporting?
#
logmessage "INFO" "Script seems to have completed successfully." "$loglocation"
echo $runhost $rundate "Script seems to have completed successfully." | $(/usr/bin/mail -s "Firmware Password Manager report" "$mailto")

exit 0

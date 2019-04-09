#!/usr/bin/python

# Copyright (c) 2019 University of Utah, Marriott Library, #####################
# Client Platform Services. All Rights Reserved.
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

# remotely_set_firmwarepassword_scp_keyfile.py #################################
#
# A Python script to demonstrate usage of Firmware Password Manager from Casper
# or other managed environment.
#
#    1.0.0  2016.03.07      Initial release. tjm
#
################################################################################

import subprocess
import os
import pexpect
import management_tools

def main():
    #
    # set these variables for your environment.
    scp_user =            'yourAccount'
    scp_password =        'yourPassword'
    scp_server =          'yourServer'
    keyfile_remote_path = '/your/remote/keyfile.txt'
    keyfile_local_path =  '/your/local/keyfile.txt'

    fwpw_manager_path =   '/usr/local/bin/firmware_password_manager.py'
    fwpw_manager_flags =  '-k ' + keyfile_local_path + ' -s -#'
    fwpw_manager_command = fwpw_manager_path + " " + fwpw_manager_flags

    if os.geteuid():
        print "Must be root to run script."
        exit(2)

    try:

        #
        # scp keyfile
        child = pexpect.spawn("/usr/bin/scp " + scp_user + "@" + scp_server + ":" + keyfile_remote_path + " " + keyfile_local_path)

        exit_condition = False
        while not exit_condition:
            result = child.expect(['^.*100\%', 'Password:', 'A.*\(yes/no\)\?', 'ssh.*refused$', '.*denied', pexpect.EOF, pexpect.TIMEOUT])
            if result == 0:
                print "keyfile aquired."
                break
            if result == 1:
                child.sendline(scp_password)
                print "password sent"
            elif result == 2:
                child.sendline("yes")
                print "fingerprint accepted"
            else:
                if result == 3:
                    print "Connection refused. Exiting."
                elif result == 4:
                    print "Password refused. Exiting."
                elif result == 5:
                    print "Unexpected EOF. Exiting."
                elif result == 6:
                    print "Connection timeout. Exiting."
                else:
                    print "Unknown error. Exiting."
                child.close()
                quit()

    except Exception as e:
        print "Unknown error [%s]. Exiting." % e
        quit()

    #
    # launch fwpm
    try:
        fwpw_man_results = subprocess.check_output(fwpw_manager_path + " " + fwpw_manager_flags, shell=True)
    except Exception as e:
        print e

if __name__ == '__main__':
    main()

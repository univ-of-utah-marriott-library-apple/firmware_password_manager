#!/usr/bin/env python

# Copyright (c) 2015 University of Utah Student Computing Labs. ################
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

# firmware_password_manager.py #################################################
#
# A Python script to help Macintosh administrators manage the firmware passwords
# of their computers.
#
#
#    2.0.0    2015.11.05    Initial python rewrite. tjm
#
#
#
# keyfile format:
#
# | comment:passwords    <-- comments are ignored, except for new.
# | new:newpassword      <-- the new password to be installed.
#
################################################################################

# notes: #######################################################################
#
#
################################################################################

# external tool documentation ##################################################
#
# firmwarepasswd v 1.0
# Copyright (C) 2014 Apple Inc.  All Rights Reserved.
#
#
# Usage: firmwarepasswd [OPTION]
#
#      ?                          Show usage
#      -h                         Show usage
#      -setpasswd                 Set a firmware password. You will be promted for passwords as needed.
#                                    NOTE: if this is the first password set, and no mode is
#                                    in place, the mode will automatically be set to "command"
#      -setmode [mode]            Set mode to:
#                                    "command" - password required to change boot disk
#                                    "full" - password required on all startups
#                                    NOTE: cannot set a mode without having set a password
#      -mode                      Prints out the current mode setting
#      -check                     Prints out whether there is / isn't a firmware password is set
#      -delete                    Delete current firmware password and mode setting
#      -verify                    Verify current firmware password
#      -unlockseed                Generates a firmware password recovery key
#                                    NOTE: Machine must be stable for this command to generate
#                                          a valid seed.  No pending changes that need a restart.
#                                    NOTE: Seed is only valid until the next time a firmware password
#                                          command occurs.
#
################################################################################

#
# imports
from management_tools import loggers
from sys import exit
import argparse
import os
import pexpect
import re
import socket
import subprocess

#
# functions
def secure_delete_keyfile(logger, args):
    """
    attempts to securely delete the keyfile with medium overwrite and zeroing settings
    """

    logger.info("Deleting keyfile")
    if args.testmode:
        logger.info("Test mode, keyfile not deleted.")
        return;
    try:
        deleted_keyfile = subprocess.call(["/usr/bin/srm", "-mz", args.keyfile])
    except:
        logger.critical("Issue with attempt to remove keyfile.")


# is this really needed?
    if os.path.exists(args.keyfile):
        logger.critical("Failure to remove keyfile.")
    else:
        logger.info("Keyfile removed.")
    return;

def send_slack_message(message, alert_level, local_identifier):
    """
    sends messages to slack with incoming_webhook integration. Accepts message text and
    message serverity.
    """

    slack_error_url     = 'https://hooks.slack.com/services/your_error_channel'
    slack_error_channel = '#your_errors'
    slack_info_url      = 'https://hooks.slack.com/services/your_info_channel'
    slack_info_channel  = '#your_info'

    if alert_level is 'success':
        emoji         = ":white_check_mark:"
        slack_url     = slack_info_url
        slack_channel = slack_info_channel
    elif alert_level is 'warning':
        emoji         = ":warning:"
        slack_url     = slack_error_url
        slack_channel = slack_error_channel
    elif alert_level is 'critical':
        emoji         = ":red_circle:"
        slack_url     = slack_error_url
        slack_channel = slack_error_channel
    elif alert_level is 'remove':
        emoji         = ":free:"
        slack_url     = slack_info_url
        slack_channel = slack_info_channel
    else:
        emoji = ""
        slack_url = slack_info_url
        slack_channel = slack_info_channel

    full_message = "_*" + local_identifier + "*_ " + emoji +"\n" + "*[" + alert_level + "]* " + message
    packed_message = '"text": "' + full_message +  '"'
    channel = '"channel": "' + slack_channel +  '"'
    username = '"username": "' + 'webhookbot' +  '"'

    payload = 'payload={' + channel + ', ' + username + ', ' + packed_message + '}'

    try:
        slack_reply = subprocess.check_call(["/usr/bin/curl", "-v", "-X", "POST", "--data-urlencode", payload, slack_url])
    except:
        logger.critical("Error attempting to curl to slack.")

    return;


def main():

    #
    # require root to run.
    if os.geteuid():
        print "Must be root to script."
        exit(2)

    #
    # parse option definitions
    parser = argparse.ArgumentParser(description='Manages the firmware password on Apple Computers.')
    parser.add_argument('-r', '--remove', action="store_true", default=False, help='Remove firmware password')
    parser.add_argument('-k', '--keyfile', help='Set path to keyfile', required=True)
    parser.add_argument('-t', '--testmode', action="store_true", default=False, help='Test mode. Verbose logging, will not delete keyfile.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 2.0.0')
    parser.add_argument('-m', '--management', default=None, help='Set nvram management string')
    parser.add_argument('-#', '--hash', action="store_true", default=False, help='Set nvram string to hash of keyfile')
    parser.add_argument('-n', '--nostring', action="store_true", default=False, help='Do not set nvram management string')
    parser.add_argument('-s', '--slack', action="store_true", default=False, help='Send important messages to Slack.')
    args = parser.parse_args()

    if args.testmode:
        print args

    #
    # Open log file
    logger = loggers.file_logger(name='FWPW_Manager2')
    logger.info("Running Firmware Password Manager 2")

    #
    # test flags for conflicts
    if args.management is not None and (args.hash or args.nostring or args.remove):
        conflicting_flags = True
    elif args.hash and (args.nostring or args.remove):
        conflicting_flags = True
    elif args.nostring and args.remove:
        conflicting_flags = True
    else:
        conflicting_flags = False

    if conflicting_flags:
        logger.info("Remove, Hash, Management and \'No string\' flags are mutually exclusive. Select one. Exiting.")
        secure_delete_keyfile(logger, args)
        exit(2)
    else:
        logger.info("Flags okay.")

    #
    # check for no flags set.
    if args.management is None and not args.hash and not args.nostring and not args.remove:
        logger.critical("A specific flag is required: Remove, Hash, Management and \'No string\'. Select one. Exiting.")
        secure_delete_keyfile(logger, args)
        exit(2)

    #
    # get local Local identifier
    local_identifier = socket.gethostbyname(socket.gethostname())
    if args.testmode:
        print "Local identifier: %r" % local_identifier

    #
    # if we get localhost or no return, use serial number instead.
    if (local_identifier == '127.0.0.1') or (local_identifier == ''):
        # logger.info ('Reporting $s as IP, hrm....' % local_identifier)

        if args.slack:
            full_ioreg    = subprocess.check_output(['ioreg', '-l'])
            pattern       = '(IOPlatformSerialNumber.*)'
            serial_data_raw   = re.findall(pattern, full_ioreg)
            serial_data_raw   = serial_data_raw[0]
            serial_number = serial_data_raw.split("= ")[1]
            serial_number = re.findall('(\w*)', serial_number)[1]
            if args.testmode:
                print "Serial number :%r" % serial_number
            logger.info("Serial number :%r" % serial_number)

            local_identifier = serial_number

    #
    # keyfile checks
    path_to_keyfile_exists = os.path.exists(args.keyfile)

    if not path_to_keyfile_exists:
        logger.critical("%s does not exist. Exiting." % args.keyfile)
        if args.slack:
            send_slack_message("Keyfile does not exist.", 'critical', local_identifier)
        exit(2)

    #
    # generate hash from incoming keyfile
    logger.info("Checking incoming hash.")
    if args.management:
        fwpw_managed_string = args.management
    elif args.hash:
        incoming_hash       = subprocess.check_output(["/usr/bin/openssl", "dgst", "-sha256", args.keyfile])
        incoming_hash       = incoming_hash.rstrip('\r\n')
        fwpw_managed_string = incoming_hash.split(" ")[1]
        # prepend '2:' to denote hash created with v2 of script, will force a password change from v1
        fwpw_managed_string = '2:' + fwpw_managed_string
    else:
    	fwpw_managed_string = None

    if args.testmode:
        print "Incoming hash: %s" % fwpw_managed_string


    #
    # compare incoming hash with current nvram hash
    existing_keyfile_hash = None
    logger.info("Checking existing hash.")
    if not args.remove:
        try:
            existing_keyfile_hash = subprocess.check_output(["/usr/sbin/nvram", "fwpw-hash"])
            existing_keyfile_hash = existing_keyfile_hash.rstrip('\r\n')
            existing_keyfile_hash = existing_keyfile_hash.split("\t")[1]

            if args.testmode:
                print "Existing hash: %s" % existing_keyfile_hash

        except Exception as this_Exception:
            logger.warning("nvram failed on %r (value probably doesn't exist)." % this_Exception)

        matching_passwords = False
        if existing_keyfile_hash == fwpw_managed_string:
            matching_passwords = True
            if args.slack:
                send_slack_message("Hashes match. No Change.", 'success', local_identifier)
            if args.hash:
                logger.info("Hashes match. Exiting.")
            elif args.management:
                logger.info("FWPW managed. Exiting.")
            secure_delete_keyfile(logger, args)
            # return a value?
            exit(0)

    #
    # firmwarepasswd tool checks
    new_fw_tool_path = '/usr/sbin/firmwarepasswd'
    new_fw_tool_exists = os.path.exists(new_fw_tool_path)

    if not new_fw_tool_exists:
        logger.critical("No Firmware password tool available. Exiting.")
        secure_delete_keyfile(logger, args)
        if args.slack:
            send_slack_message("No Firmware password tool available.", 'critical', local_identifier)
        exit(1)

    #
    # checking for existing fw password
    logger.info("Checking for existing firmware password")

    existing_fw_pw = subprocess.check_output([new_fw_tool_path, "-check"])
    logger.info("New tools says %r " % existing_fw_pw)
    if 'No' in existing_fw_pw:
        if args.remove:
            logger.critical("Asked to delete, no password set. Exiting.")
            secure_delete_keyfile(logger, args)
            if args.slack:
                send_slack_message("Asked to Delete, no password set.", 'critical', local_identifier)
            exit(1)
        else:
            logger.info("No firmware password set.")
            existing_password = False
    elif 'Yes' in existing_fw_pw:
        logger.info("Existing firmware password set.")
        existing_password = True
    else:
        logger.critical("Firmwarepasswd bad response at -check. Exiting.")
        secure_delete_keyfile(logger, args)
        if args.slack:
            send_slack_message("Firmwarepasswd bad response at -check.", 'critical', local_identifier)
        exit(1)

    #
    # read keyfile
    logger.info("Reading password file")

    with open(args.keyfile) as f:
        passwords = f.read().splitlines()
    f.close()

    logger.info("Closed password file")

    new_password = None
    other_password_list = []

    #
    # parse data from keyfile and build list of passwords
    for entry in passwords:
        try:
            key, value = entry.split(":", 1)
        except Exception as this_Exception:
            logger.critical("Malformed keyfile, key:value format required. %r. Quitting." % this_Exception)
            secure_delete_keyfile(logger, args)
            if args.slack:
                send_slack_message("Malformed keyfile.", 'critical', local_identifier)
            exit(1)

        if args.testmode:
            logger.info('%s:%s' % (key, value))

        if key.lower() == 'new':
            if new_password is not None:
                logger.critical("Malformed keyfile, multiple new keys. Quitting.")
                secure_delete_keyfile(logger, args)
                if args.slack:
                    send_slack_message("Malformed keyfile.", 'critical', local_identifier)
                exit(1)
            else:
                new_password = value
                other_password_list.append(value)
        else:
            other_password_list.append(value)

    logger.info("Sanity checking password file contents")

    if new_password is None and not args.remove:
            logger.critical("Malformed keyfile, no \'new\' key. Quitting.")
            secure_delete_keyfile(logger, args)
            if args.slack:
                send_slack_message("Malformed keyfile.", 'critical', local_identifier)
            exit(1)

    exit_Normal = False
    known_current_password = False

    #
    # if a password is set, attempt to discover it using keyfile
    if existing_password:
        logger.info("Verifying current FW password")
        new_fw_tool_cmd = [new_fw_tool_path, '-verify']
        logger.info(' '.join(new_fw_tool_cmd))

        for index in reversed(xrange(len(other_password_list))):
            child = pexpect.spawn(' '.join(new_fw_tool_cmd))
            child.expect('Enter password:')

            child.sendline(other_password_list[index])
            result = child.expect(['Correct', 'Incorrect'])

            if result == 0:
                #
                # correct password, exit loop
                current_password = other_password_list[index]
                known_current_password = True
                break
            else:
                #
                # wrong password, keep going
                continue

        #
        # We've discovered the currently set firmware password
        if known_current_password:

            #
            # Deleting firmware password
            if args.remove:
                logger.info("Deleting FW password")

                new_fw_tool_cmd = [new_fw_tool_path, '-delete']
                logger.info(' '.join(new_fw_tool_cmd))

                child = pexpect.spawn(' '.join(new_fw_tool_cmd))
                child.expect('Enter password:')

                child.sendline(current_password)
                result = child.expect(['removed', 'incorrect'])

                if result == 0:
                    #
                    # password accepted, log result and exit
                    logger.info("Finished. Password should be removed. Restart required. [%i]" % (index + 1))
                    exit_Normal = True
                else:
                    logger.critical("Asked to delete, current password not accepted. Exiting.")
                    secure_delete_keyfile(logger, args)
                    if args.slack:
                        send_slack_message("Asked to delete, current password not accepted.", 'critical', local_identifier)
                    exit(1)

            #
            # Current and new password are identical
            elif current_password == new_password:
                logger.info("Match, no change required. Exiting.")
                exit_Normal = True

            #
            # Change current firmware password to new password
            else:
                logger.info("Updating FW password")

                new_fw_tool_cmd = [new_fw_tool_path, '-setpasswd']
                logger.info(' '.join(new_fw_tool_cmd))

                child = pexpect.spawn(' '.join(new_fw_tool_cmd))

                result = child.expect('Enter password:')
                if result == 0:
                    pass
                else:
                    logger.error("bad response from firmwarepasswd. Exiting.")
                    secure_delete_keyfile(logger, args)
                    if args.slack:
                        send_slack_message("Bad response from firmwarepasswd.", 'critical', local_identifier)
                    exit(1)
                child.sendline(current_password)

                result = child.expect('Enter new password:')
                if result == 0:
                    pass
                else:
                    logger.error("bad response from firmwarepasswd. Exiting.")
                    secure_delete_keyfile(logger, args)
                    if args.slack:
                        send_slack_message("Bad response from firmwarepasswd.", 'critical', local_identifier)
                    exit(1)
                child.sendline(new_password)

                result = child.expect('Re-enter new password:')
                if result == 0:
                    pass
                else:
                    logger.error("bad response from firmwarepasswd. Exiting.")
                    secure_delete_keyfile(logger, args)
                    if args.slack:
                        send_slack_message("Bad response from firmwarepasswd.", 'critical', local_identifier)
                    exit(1)
                child.sendline(new_password)

                child.expect(pexpect.EOF)
                child.close()

                logger.info("Updated FW Password.")
                exit_Normal = True

        #
        # Unable to match current password with contents of keyfile
        else:
            logger.critical("Current FW password not in keyfile. Quitting.")
            secure_delete_keyfile(logger, args)
            if args.slack:
                send_slack_message("Current FW password not in keyfile.", 'critical', local_identifier)
            exit(1)

    #
    # No current firmware password, setting it
    else:
        new_fw_tool_cmd = [new_fw_tool_path, '-setpasswd']
        logger.info(' '.join(new_fw_tool_cmd))

        child = pexpect.spawn(' '.join(new_fw_tool_cmd))

        result = child.expect('Enter new password:')
        print child.before
        if result == 0:
            pass
        else:
            logger.error("bad response from firmwarepasswd. Exiting.")
            secure_delete_keyfile(logger, args)
            if args.slack:
                send_slack_message("Bad response from firmwarepasswd.", 'critical', local_identifier)
            exit(1)
        child.sendline(new_password)

        result = child.expect('Re-enter new password:')
        if result == 0:
            pass
        else:
            logger.error("bad response from firmwarepasswd. Exiting.")
            secure_delete_keyfile(logger, args)
            if args.slack:
                send_slack_message("Bad response from firmwarepasswd.", 'critical', local_identifier)
            exit(1)
        child.sendline(new_password)

        child.expect(pexpect.EOF)
        child.close()

        logger.info("Added FW Password.")
        exit_Normal = True

    #
    # Delete keyfile securely.
    secure_delete_keyfile(logger, args)

    #
    # closing reports
    logger.info("Closing out.")


    #
    # No errors detected during run.
    if exit_Normal:
        if args.slack:
            if args.remove:
                send_slack_message("FWPW removed.", 'remove', local_identifier)
            else:
                send_slack_message("FWPW updated.", 'success', local_identifier)
        if not args.remove and not args.nostring and not matching_passwords:
            try:
                modify_nvram = subprocess.call(["/usr/sbin/nvram", "fwpw-hash="+fwpw_managed_string])
                logger.info("nvram modified.")
            except:
                logger.warning("nvram reported error.")
        elif args.remove or args.nostring:
            try:
                modify_nvram = subprocess.call(["/usr/sbin/nvram", "-d", "fwpw-hash"])
                logger.info("nvram pruned.")
            except:
                logger.warning("nvram reported error.")
        exit(0)

    #
    # Errors detected during run.
    else:
        logger.critical("An error occured. Failed to modify firmware password.")
        if args.slack:
            send_slack_message("An error occured. Failed to modify firmware password.", 'critical', local_identifier)
        exit(1)


if __name__ == '__main__':
    main()

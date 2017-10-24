#!/usr/bin/python
"""
A Python script to help Macintosh administrators manage the firmware passwords of their computers.
"""

# Copyright (c) 2016 University of Utah Student Computing Labs. ################
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
#    2.0.0  2015.11.05      Initial python rewrite. tjm
#
#    2.1.0  2016.03.07      "Now with spinning rims"
#                           bug fixes, obfuscation features,
#                           additional tools and examples. tjm
#
#    2.1.1  2016.03.16      slack identifier customization,
#                           logic clarifications. tjm
#
#    2.1.2  2016.03.16      cleaned up argparse. tjm
#
#    2.1.3  2016.04.04      remove obsolete flag logic. tjm
#
#    2.1.4  2017.10.23      using rm -P for secure delete,
#                           added additional alerting, additional pylint cleanup. tjm
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
#
#
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
# from sys import exit
import argparse
import os
import re
import socket
import subprocess
import plistlib
import base64
import pexpect
from management_tools import loggers
from management_tools.slack import IncomingWebhooksSender as IWS


#
# functions
def secure_delete_keyfile(logger, args, error_bot, local_identifier):
    """
    attempts to securely delete the keyfile with medium overwrite and zeroing settings
    """

    logger.info("Deleting keyfile")
    if args.testmode:
        logger.info("Test mode, keyfile not deleted.")
        return
    try:
        deleted_keyfile = subprocess.call(["/bin/rm", "-Pf", args.keyfile])
        logger.info("keyfile deleted successfuly.")
    except:
        logger.critical("Issue with attempt to remove keyfile.")


# is this really needed?
    if os.path.exists(args.keyfile):
        logger.critical("Failure to remove keyfile.")
        if args.slack:
            error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "An error occured. Failed to remove keyfile.")
    else:
        logger.info("Keyfile removed.")
    return


def main():
    """
    Master Control Function.
    """

    #
    # require root to run.
    if os.geteuid():
        print "Must be root to run script."
        exit(2)

    #
    # parse option definitions
    parser = argparse.ArgumentParser(
        description='Manages the firmware password on Apple Computers.')
    #
    # required, mutually exclusive commands
    prime_group = parser.add_argument_group('Required management settings',
                                            'Choosing one of these options is required \
                                            to run FWPM. They tell FWPM how you \
                                            want to manage the firmware password.')
    subprime = prime_group.add_mutually_exclusive_group(required=True)
    subprime.add_argument('-r', '--remove', action="store_true",
                          default=False, help='Remove the firmware password')
    subprime.add_argument('-m', '--management', default=None,
                          help='Set a custom nvram management string')
    subprime.add_argument('-#', '--hash', action="store_true", default=False,
                          help='Set nvram string to hash of keyfile')
    subprime.add_argument('-n', '--nostring', action="store_true", default=False,
                          help='Do not set an nvram management string')

    keyfile_group = parser.add_argument_group('Keyfile options', 'The keyfile is \
                                               required to use FWPM. These options \
                                               allow you to set the location and \
                                               format of the keyfile.')
    keyfile_group.add_argument('-k', '--keyfile', help='Set the path to your keyfile',
                               required=True)
    keyfile_group.add_argument('-o', '--obfuscated', action="store_true", default=False,
                               help='Tell FWPM your keylist is an obfuscated plist.')

    slack_group = parser.add_argument_group('Slack integration',
                                            'FWPM allows you to send informational \
                                            and error messages to your Slack team. \
                                            Additionally you can select different \
                                            methods of identifiying clients.')
    slack_group.add_argument('-s', '--slack', action="store_true",
                             default=False, help='Send important messages to Slack.')
    slack_group.add_argument('-i', '--identifier', default=None,
                             choices=['IP', 'hostname', 'MAC', 'computername', 'serial'],
                             required=False, help='Set slack identifier.')

    parser.add_argument('-b', '--reboot', action="store_true", default=False,
                        help='Reboots the computer after the script completes successfully.')
    parser.add_argument('-t', '--testmode', action="store_true", default=False,
                        help='Test mode. Verbose logging, will not delete keyfile.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 2.1.4')

    args = parser.parse_args()

    if args.testmode:
        print args

    #
    # Open log file
    logger = loggers.file_logger(name='FWPW_Manager2')
    logger.info("Running Firmware Password Manager 2")

    #
    # set up slack channel(s)
    slack_info_url = 'your FWPM slack info URL'
    slack_info_channel = '#your FWPM slack info channel'
    info_bot = IWS(slack_info_url, bot_name="FWPM informational message", channel=slack_info_channel)

    slack_error_url = 'your FWPM slack error URL'
    slack_error_channel = '#your FWPM slack error channel'
    error_bot = IWS(slack_error_url, bot_name="FWPM error message", channel=slack_error_channel)

    local_identifier = None

    if args.slack:
        full_ioreg = subprocess.check_output(['ioreg', '-l'])
        serial_number_raw = re.findall(r'\"IOPlatformSerialNumber\" = \"(.*)\"', full_ioreg)
        serial_number = serial_number_raw[0]
        if args.testmode:
            print "Serial number: %r" % serial_number

        if args.identifier == 'IP' or args.identifier == 'MAC' or args.identifier == 'hostname':
            processed_device_list = []

            # Get ordered list of network devices
            base_network_list = subprocess.check_output(["/usr/sbin/networksetup", "-listnetworkserviceorder"])
            network_device_list = re.findall(r'\) (.*)\n\(.*Device: (.*)\)', base_network_list)
            for device in network_device_list:
                device_name = device[0]
                port_name = device[1]
                try:
                    device_info_raw = subprocess.check_output(["/sbin/ifconfig", port_name])
                    mac_address = re.findall(r'ether (.*) \n', device_info_raw)
                    if args.testmode:
                        print "%r" % mac_address
                    ether_address = re.findall(r'inet (.*) netmask', device_info_raw)
                    if args.testmode:
                        print "%r" % ether_address
                    processed_device_list.append([device_name, port_name, ether_address[0], mac_address[0]])
                except:
                    pass

            if len(processed_device_list) > 0:
                logger.info("1 or more active IP addresses. Choosing primary.")
                if args.testmode:
                    print processed_device_list
                if args.identifier == 'IP':
                    local_identifier = processed_device_list[0][2] + " (" + processed_device_list[0][0] + ":" + processed_device_list[0][1] + ")"

                if args.identifier == 'MAC':
                    local_identifier = processed_device_list[0][3] + " (" + processed_device_list[0][0] + ":" + processed_device_list[0][1] + ")"

                if args.identifier == 'hostname':
                    try:
                        local_identifier = socket.getfqdn()
                    except:
                        logger.error("error discovering hostname info.")
                        local_identifier = serial_number

            elif len(processed_device_list) == 0:
                logger.error("error discovering IP info.")
                local_identifier = serial_number

        elif args.identifier == 'computername':
            try:
                cname_identifier_raw = subprocess.check_output(['/usr/sbin/scutil', '--get', 'ComputerName'])
                local_identifier = cname_identifier_raw.split('\n')[0]
                logger.info("Computername: " + local_identifier)
            except:
                logger.info("error discovering computername.")
                local_identifier = serial_number
        elif args.identifier == 'serial':
            local_identifier = serial_number
            logger.info("Serial number: " + local_identifier)
        else:
            logger.info("bad or no identifier flag, defaulting to serial number.")
            local_identifier = serial_number

        if args.testmode:
            print "Local identifier: %r" % local_identifier

    #
    # keyfile checks
    path_to_keyfile_exists = os.path.exists(args.keyfile)

    if not path_to_keyfile_exists:
        logger.critical(args.keyfile + " does not exist. Exiting.")
        if args.slack:
            error_bot.send_message("_*" + local_identifier + "*_ :no_entry_sign:\n" + "Keyfile does not exist.")
        exit(2)

    #
    # generate hash from incoming keyfile
    logger.info("Checking incoming hash.")
    if args.management:
        fwpw_managed_string = args.management
    elif args.hash:
        incoming_hash = subprocess.check_output(["/usr/bin/openssl", "dgst", "-sha256", args.keyfile])
        incoming_hash = incoming_hash.rstrip('\r\n')
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

        except Exception as this_exception:
            logger.warning("nvram failed on " + this_exception + " (value probably doesn't exist).")

        if existing_keyfile_hash == fwpw_managed_string:
            if args.hash:
                logger.info("Hashes match. Exiting.")
                if args.slack:
                    info_bot.send_message("_*" + local_identifier + "*_ :white_check_mark:\n" + "Hashes match. No Change.")
                secure_delete_keyfile(logger, args, error_bot, local_identifier)
                if args.reboot:
                    logger.info("Reboot not required, canceling.")
                # return a value?
                exit(0)
            else:
                logger.info("Management strings match. Continuing.")

    #
    # firmwarepasswd tool checks
    new_fw_tool_path = '/usr/sbin/firmwarepasswd'
    new_fw_tool_exists = os.path.exists(new_fw_tool_path)

    if not new_fw_tool_exists:
        logger.critical("No Firmware password tool available. Exiting.")
        secure_delete_keyfile(logger, args, error_bot, local_identifier)
        if args.slack:
            error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "No Firmware password tool available.")
        exit(1)

    #
    # checking for existing fw password
    logger.info("Checking for existing firmware password")

    existing_fw_pw = subprocess.check_output([new_fw_tool_path, "-check"])
    logger.info("New tools says " + existing_fw_pw)
    if 'No' in existing_fw_pw:
        if args.remove:
            logger.critical("Asked to delete, no password set. Exiting.")
            secure_delete_keyfile(logger, args, error_bot, local_identifier)
            if args.slack:
                error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "Asked to Delete, no password set.")
            try:
                modify_nvram = subprocess.call(["/usr/sbin/nvram", "-d", "fwpw-hash"])
                logger.info("nvram entry pruned.")
            except:
                logger.warning("nvram reported error attempting to remove hash. Hash may not have existed.")
            exit(1)
        else:
            logger.info("No firmware password set.")
            existing_password = False
    elif 'Yes' in existing_fw_pw:
        logger.info("Existing firmware password set.")
        existing_password = True
    else:
        logger.critical("Firmwarepasswd bad response at -check. Exiting.")
        secure_delete_keyfile(logger, args, error_bot, local_identifier)
        if args.slack:
            error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "Firmwarepasswd bad response at -check.")
        exit(1)

    logger.info("Reading password file")

    if args.obfuscated:
        #
        # unobfuscate plist
        logger.info("Reading plist")
        passwords = []
        try:
            input_plist = plistlib.readPlist(args.keyfile)
        except:
            logger.critical("Error reading plist. Exiting.")
            if args.slack:
                error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "Error reading plist.")
            exit(1)
        content_raw = input_plist["data"]

        content_raw = base64.b64decode(content_raw)
        content_raw = content_raw.split(",")
        content_raw = [x for x in content_raw if x]

        for item in content_raw:
            label, pword = item.split(':')
            pword = base64.b64decode(pword)
            try:
                commented = label.split('#')[1]
                commented = base64.b64decode(commented)
                is_commented = True
            except:
                is_commented = False

            if is_commented:
                output_string = "#" + commented + ":"+pword
            else:
                output_string = label + ":"+pword
            passwords.append(output_string)

    else:
        #
        #  read keyfile
        logger.info("Reading plain text")

        try:
            with open(args.keyfile, "r") as keyfile:
                passwords = keyfile.read().splitlines()
        except:
            logger.critical("Error reading keyfile. Exiting.")
            if args.slack:
                error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "Error reading keyfile.")
            exit(1)

        logger.info("Closed password file")

    new_password = None
    other_password_list = []

    #
    # parse data from keyfile and build list of passwords
    for entry in passwords:
        try:
            key, value = entry.split(":", 1)
        except Exception as this_exception:
            logger.critical("Malformed keyfile, key:value format required. " + this_exception + ". Quitting.")
            secure_delete_keyfile(logger, args, error_bot, local_identifier)
            if args.slack:
                error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "Malformed keyfile.")
            exit(1)

        if args.testmode:
            logger.info(key + ":" + value)

        if key.lower() == 'new':
            if new_password is not None:
                logger.critical("Malformed keyfile, multiple new keys. Quitting.")
                secure_delete_keyfile(logger, args, error_bot, local_identifier)
                if args.slack:
                    error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "Malformed keyfile.")
                exit(1)
            else:
                new_password = value
                other_password_list.append(value)
        else:
            other_password_list.append(value)

    logger.info("Sanity checking password file contents")

    if new_password is None and not args.remove:
        logger.critical("Malformed keyfile, no \'new\' key. Quitting.")
        secure_delete_keyfile(logger, args, error_bot, local_identifier)
        if args.slack:
            error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "Malformed keyfile.")
        exit(1)

    exit_normal = False
    known_current_password = False

    #
    # if a password is set, attempt to discover it using keyfile
    if existing_password:
        logger.info("Verifying current FW password")
        new_fw_tool_cmd = [new_fw_tool_path, '-verify']
        logger.info(' '.join(new_fw_tool_cmd))

        for keyfile_index in reversed(xrange(len(other_password_list))):
            child = pexpect.spawn(' '.join(new_fw_tool_cmd))
            child.expect('Enter password:')

            child.sendline(other_password_list[keyfile_index])
            result = child.expect(['Correct', 'Incorrect'])

            if result == 0:
                #
                # correct password, exit loop
                current_password = other_password_list[keyfile_index]
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
                    logger.info("Finished. Password should be removed. Restart required. [" + (keyfile_index + 1) + "]")
                    exit_normal = True
                else:
                    logger.critical("Asked to delete, current password not accepted. Exiting.")
                    secure_delete_keyfile(logger, args, error_bot, local_identifier)
                    if args.slack:
                        error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "Asked to delete, current password not accepted.")
                    exit(1)

            #
            # Current and new password are identical
            elif current_password == new_password:
                logger.info("Match, no change required. Exiting.")
                exit_normal = True

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
                    secure_delete_keyfile(logger, args, error_bot, local_identifier)
                    if args.slack:
                        error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "Bad response from firmwarepasswd.")
                    exit(1)
                child.sendline(current_password)

                result = child.expect('Enter new password:')
                if result == 0:
                    pass
                else:
                    logger.error("bad response from firmwarepasswd. Exiting.")
                    secure_delete_keyfile(logger, args, error_bot, local_identifier)
                    if args.slack:
                        error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "Bad response from firmwarepasswd.")
                    exit(1)
                child.sendline(new_password)

                result = child.expect('Re-enter new password:')
                if result == 0:
                    pass
                else:
                    logger.error("bad response from firmwarepasswd. Exiting.")
                    secure_delete_keyfile(logger, args, error_bot, local_identifier)
                    if args.slack:
                        error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "Bad response from firmwarepasswd.")
                    exit(1)
                child.sendline(new_password)

                child.expect(pexpect.EOF)
                child.close()

                logger.info("Updated FW Password.")
                exit_normal = True

        #
        # Unable to match current password with contents of keyfile
        else:
            logger.critical("Current FW password not in keyfile. Quitting.")
            secure_delete_keyfile(logger, args, error_bot, local_identifier)
            if args.slack:
                error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "Current FW password not in keyfile.")
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
            secure_delete_keyfile(logger, args, error_bot, local_identifier)
            if args.slack:
                error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "Bad response from firmwarepasswd.")
            exit(1)
        child.sendline(new_password)

        result = child.expect('Re-enter new password:')
        if result == 0:
            pass
        else:
            logger.error("bad response from firmwarepasswd. Exiting.")
            secure_delete_keyfile(logger, args, error_bot, local_identifier)
            if args.slack:
                error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "Bad response from firmwarepasswd.")
            exit(1)
        child.sendline(new_password)

        child.expect(pexpect.EOF)
        child.close()

        logger.info("Added FW Password.")
        exit_normal = True

    #
    # Delete keyfile securely.
    secure_delete_keyfile(logger, args, error_bot, local_identifier)

    #
    # closing reports
    logger.info("Closing out.")

    #
    # No errors detected during run.
    # nvram modifications, reporting, and exits
    if exit_normal:
        if args.remove:
            try:
                modify_nvram = subprocess.call(["/usr/sbin/nvram", "-d", "fwpw-hash"])
                logger.info("nvram entry pruned.")
                if args.slack:
                    info_bot.send_message("_*" + local_identifier + "*_ :unlock:\n" + "FWPW removed.")
            except:
                logger.warning("nvram reported error attempting to remove hash. Hash may not have existed.")
                exit(1)

        if args.nostring:
            try:
                existing_keyfile_hash = subprocess.check_output(["/usr/sbin/nvram", "fwpw-hash"])
                try:
                    modify_nvram = subprocess.call(["/usr/sbin/nvram", "-d", "fwpw-hash"])
                    logger.info("nvram entry pruned.")
                    if args.slack:
                        info_bot.send_message("_*" + local_identifier + "*_ :closed_lock_with_key:\n" + "FWPW updated.")
                except:
                    logger.warning("nvram reported error attempting to remove hash. Exiting.")
                    exit(1)
            except:
                # assuming hash doesn't exist.
                logger.info("Assuming nvram entry doesn't exist.")
                if args.slack:
                    info_bot.send_message("_*" + local_identifier + "*_ :closed_lock_with_key:\n" + "FWPW updated.")

        if args.management or args.hash:
            try:
                modify_nvram = subprocess.call(["/usr/sbin/nvram", "fwpw-hash="+fwpw_managed_string])
                logger.info("nvram modified.")
                if args.slack:
                    info_bot.send_message("_*" + local_identifier + "*_ :closed_lock_with_key:\n" + "FWPW updated.")
            except:
                logger.warning("nvram modification failed. nvram reported error.")
                exit(1)

        if args.reboot:
            logger.warning("Normal completion. Rebooting.")
            os.system('reboot')
        else:
            exit(0)

    #
    # Errors detected during run.
    else:
        logger.critical("An error occured. Failed to modify firmware password.")
        if args.slack:
            error_bot.send_message("_*" + local_identifier + "*_ :no_entry:\n" + "An error occured. Failed to modify firmware password.")
        exit(1)


if __name__ == '__main__':
    main()

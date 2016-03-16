#!/usr/bin/python

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
from management_tools import loggers
from management_tools.slack import IncomingWebhooksSender as IWS
from sys import exit
import argparse
import os
import pexpect
import re
import socket
import subprocess
import plistlib
import base64

#
# functions
def secure_delete_keyfile(logger, args):
    """
    attempts to securely delete the keyfile with medium overwrite and zeroing settings
    """

    logger.info("Deleting keyfile")
    if args.testmode:
        logger.info("Test mode, keyfile not deleted.")
        return
    try:
        deleted_keyfile = subprocess.call(["/usr/bin/srm", "-mz", args.keyfile])
    except:
        logger.critical("Issue with attempt to remove keyfile.")


# is this really needed?
    if os.path.exists(args.keyfile):
        logger.critical("Failure to remove keyfile.")
    else:
        logger.info("Keyfile removed.")
    return

def main():

    #
    # require root to run.
    if os.geteuid():
        print "Must be root to run script."
        exit(2)

    #
    # parse option definitions
    parser = argparse.ArgumentParser(description='Manages the firmware password on Apple Computers.')
    parser.add_argument('-r', '--remove', action="store_true", default=False, help='Remove firmware password')
    parser.add_argument('-k', '--keyfile', help='Set path to keyfile', required=True)
    parser.add_argument('-t', '--testmode', action="store_true", default=False, help='Test mode. Verbose logging, will not delete keyfile.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 2.1.0')
    parser.add_argument('-m', '--management', default=None, help='Set nvram management string')
    parser.add_argument('-#', '--hash', action="store_true", default=False, help='Set nvram string to hash of keyfile')
    parser.add_argument('-n', '--nostring', action="store_true", default=False, help='Do not set nvram management string')
    parser.add_argument('-s', '--slack', action="store_true", default=False, help='Send important messages to Slack.')
    parser.add_argument('-o', '--obfuscated', action="store_true", default=False, help='Accepts a plist containing the obfuscated keyfile.')
    parser.add_argument('-b', '--reboot', action="store_true", default=False, help='Reboots the computer after the script completes successfully.')
    parser.add_argument('-i', '--identifier', default=None, required=False, help='Set slack identifier. [IP, hostname, MAC, computername, serial]')
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
    # set up slack channel(s)
    if args.slack:
        slack_info_url      = 'your slack URL'
        slack_info_channel  = '#your FWPM info channel'
        info_bot            = IWS(slack_info_url, bot_name="FWPM informational message", channel=slack_info_channel)

        slack_error_url     = 'your slack URL'
        slack_error_channel = '#your FWPM error channel'
        error_bot           = IWS(slack_error_url, bot_name="FWPM error message", channel=slack_error_channel)

        full_ioreg        = subprocess.check_output(['ioreg', '-l'])
        serial_number_raw = re.findall('\"IOPlatformSerialNumber\" = \"(.*)\"', full_ioreg)
        serial_number     = serial_number_raw[0]
        if args.testmode:
            print "Serial number: %r" % serial_number

        if args.identifier == 'IP' or args.identifier == 'ip' or args.identifier == 'MAC' or args.identifier == 'mac' or  args.identifier == 'hostname':
            processed_device_list = []

            # Get ordered list of network devices
            base_network_list = subprocess.check_output(["/usr/sbin/networksetup", "-listnetworkserviceorder"])
            network_device_list = re.findall('\) (.*)\n\(.*Device: (.*)\)', base_network_list)
            for device in network_device_list:
                device_name = device[0]
                port_name = device[1]
                try:
                    device_info_raw = subprocess.check_output(["/sbin/ifconfig", port_name])
                    mac_address = re.findall('ether (.*) \n', device_info_raw)
                    print "%r" % mac_address
                    ether_address = re.findall('inet (.*) netmask', device_info_raw)
                    print "%r" % ether_address
                    processed_device_list.append([ device_name, port_name, ether_address[0], mac_address[0] ])
                except:
                    pass

            if len(processed_device_list) > 0:
                logger.info("Multiple active IP addresses. Choosing primary.")
                if args.testmode:
                    print processed_device_list
                if args.identifier == 'IP' or args.identifier == 'ip':
                    local_identifier = processed_device_list[0][2] + " (" + processed_device_list[0][0] + ":" + processed_device_list[0][1] + ")"

                if args.identifier == 'MAC' or args.identifier == 'mac':
                    local_identifier = processed_device_list[0][3]  + " (" + processed_device_list[0][0] + ":" + processed_device_list[0][1] + ")"

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
                logger.info("Computername: %r" % local_identifier)
            except:
                logger.info("error discovering computername.")
                local_identifier = serial_number
        elif args.identifier == 'serial':
            local_identifier = serial_number
            logger.info("Serial number: %r" % local_identifier)
        else:
            logger.info("bad or no identifier flag, defaulting to serial number.")
            local_identifier = serial_number

        if args.testmode:
            print "Local identifier: %r" % local_identifier

    #
    # keyfile checks
    path_to_keyfile_exists = os.path.exists(args.keyfile)

    if not path_to_keyfile_exists:
        logger.critical("%s does not exist. Exiting." % args.keyfile)
        if args.slack:
            error_bot.send_message("_*"+local_identifier + "*_ :no_entry_sign:\n" + "Keyfile does not exist.")
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

        if existing_keyfile_hash == fwpw_managed_string:
            if args.hash:
                logger.info("Hashes match. Exiting.")
                if args.slack:
                    info_bot.send_message("_*"+local_identifier + "*_ :white_check_mark:\n" + "Hashes match. No Change.")
                secure_delete_keyfile(logger, args)
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
        secure_delete_keyfile(logger, args)
        if args.slack:
            error_bot.send_message("_*"+local_identifier + "*_ :no_entry:\n" + "No Firmware password tool available.")
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
                error_bot.send_message("_*"+local_identifier + "*_ :no_entry:\n" + "Asked to Delete, no password set.")
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
        secure_delete_keyfile(logger, args)
        if args.slack:
            error_bot.send_message("_*"+local_identifier + "*_ :no_entry:\n" + "Firmwarepasswd bad response at -check.")
        exit(1)


    logger.info("Reading password file")

    if args.obfuscated:
        #
        # unobfuscate plist
        logger.info("Reading plist")
        passwords = []
        try:
            pl = plistlib.readPlist(args.keyfile)
        except:
            logger.critical("Error reading plist. Exiting.")
            if args.slack:
                error_bot.send_message("_*"+local_identifier + "*_ :no_entry:\n" + "Error reading plist.")
            exit(1)
        content_raw = pl["data"]

        content_raw = base64.b64decode(content_raw)
        content_raw = content_raw.split(",")
        content_raw = [x for x in content_raw if x]

        for x in content_raw:
            label, pword = x.split(':')
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
                error_bot.send_message("_*"+local_identifier + "*_ :no_entry:\n" + "Error reading keyfile.")
            exit(1)

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
                error_bot.send_message("_*"+local_identifier + "*_ :no_entry:\n" + "Malformed keyfile.")
            exit(1)

        if args.testmode:
            logger.info('%s:%s' % (key, value))

        if key.lower() == 'new':
            if new_password is not None:
                logger.critical("Malformed keyfile, multiple new keys. Quitting.")
                secure_delete_keyfile(logger, args)
                if args.slack:
                    error_bot.send_message("_*"+local_identifier + "*_ :no_entry:\n" + "Malformed keyfile.")
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
                error_bot.send_message("_*"+local_identifier + "*_ :no_entry:\n" + "Malformed keyfile.")
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
                        error_bot.send_message("_*"+local_identifier + "*_ :no_entry:\n" + "Asked to delete, current password not accepted.")
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
                        error_bot.send_message("_*"+local_identifier + "*_ :no_entry:\n" + "Bad response from firmwarepasswd.")
                    exit(1)
                child.sendline(current_password)

                result = child.expect('Enter new password:')
                if result == 0:
                    pass
                else:
                    logger.error("bad response from firmwarepasswd. Exiting.")
                    secure_delete_keyfile(logger, args)
                    if args.slack:
                        error_bot.send_message("_*"+local_identifier + "*_ :no_entry:\n" + "Bad response from firmwarepasswd.")
                    exit(1)
                child.sendline(new_password)

                result = child.expect('Re-enter new password:')
                if result == 0:
                    pass
                else:
                    logger.error("bad response from firmwarepasswd. Exiting.")
                    secure_delete_keyfile(logger, args)
                    if args.slack:
                        error_bot.send_message("_*"+local_identifier + "*_ :no_entry:\n" + "Bad response from firmwarepasswd.")
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
                error_bot.send_message("_*"+local_identifier + "*_ :no_entry:\n" + "Current FW password not in keyfile.")
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
                error_bot.send_message("_*"+local_identifier + "*_ :no_entry:\n" + "Bad response from firmwarepasswd.")
            exit(1)
        child.sendline(new_password)

        result = child.expect('Re-enter new password:')
        if result == 0:
            pass
        else:
            logger.error("bad response from firmwarepasswd. Exiting.")
            secure_delete_keyfile(logger, args)
            if args.slack:
                error_bot.send_message("_*"+local_identifier + "*_ :no_entry:\n" + "Bad response from firmwarepasswd.")
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
    # nvram modifications, reporting, and exits
    if exit_Normal:
        if args.remove:
            try:
                modify_nvram = subprocess.call(["/usr/sbin/nvram", "-d", "fwpw-hash"])
                logger.info("nvram entry pruned.")
                if args.slack:
                    info_bot.send_message("_*"+local_identifier + "*_ :unlock:\n" + "FWPW removed.")
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
                        info_bot.send_message("_*"+local_identifier + "*_ :closed_lock_with_key:\n" + "FWPW updated.")
                except:
                    logger.warning("nvram reported error attempting to remove hash. Exiting.")
                    exit(1)
            except:
                # assuming hash doesn't exist.
                logger.info("Assuming nvram entry doesn't exist.")
                if args.slack:
                    info_bot.send_message("_*"+local_identifier + "*_ :closed_lock_with_key:\n" + "FWPW updated.")

        if args.management or args.hash:
            try:
                modify_nvram = subprocess.call(["/usr/sbin/nvram", "fwpw-hash="+fwpw_managed_string])
                logger.info("nvram modified.")
                if args.slack:
                    info_bot.send_message("_*"+local_identifier + "*_ :closed_lock_with_key:\n" + "FWPW updated.")
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
            error_bot.send_message("_*"+local_identifier + "*_ :no_entry:\n" + "An error occured. Failed to modify firmware password.")
        exit(1)

if __name__ == '__main__':
    main()

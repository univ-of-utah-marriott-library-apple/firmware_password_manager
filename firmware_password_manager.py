#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
This should not be blank.
"""

# Copyright (c) 2020 University of Utah Student Computing Labs. ################
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
#    2.5.0  2017.11.14      removed flags, uses configuration file,
#                           reintroduced setregproptool functionality,
#                           removed management_tools, ported to
#                           python3, added testing fuctionality. tjm
#
#    2.5.0  2020.01.23      2.5 actually finished and committed. tjm
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
#   ./firmware_password_manager_cfg_v2.5b3.py -c private.INI -t
#
#
#   sudo pyinstaller --onefile firmware_password_manager.py
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
#
#
# setregproptool v 2.0 (9) Aug 24 2013
# Copyright (C) 2001-2010 Apple Inc.
# All Rights Reserved.
#
# Usage: setregproptool [-c] [-d [-o <old password>]] [[-m <mode> -p <password>] -o <old password>]
#
#     -c              Check whether password is enabled.
#                             Sets return status of 0 if set, 1 otherwise.
#     -d              Delete current password/mode.
#                             Requires current password on some machines.
#     -p              Set password.
#                             Requires current password on some machines.
#     -m              Set security mode.
#                             Requires current password on some machines.
#                             Mode can be either "full" or "command".
#                             Full mode requires entry of the password on
#                             every boot, command mode only requires entry
#                             of the password if the boot picker is invoked
#                             to select a different boot device.
#
#                     When enabling the Firmware Password for the first
#                     time, both the password and mode must be provided.
#                     Once the firmware password has been enabled, providing
#                     the mode or password alone will change that parameter
#                     only.
#
#     -o              Old password.
#                             Only required on certain machines to disable
#                             or change password or mode. Optional, if not
#                             provided the tool will prompt for the password.
#
################################################################################

#
# imports
from argparse import RawTextHelpFormatter
import argparse
import base64
import configparser
import hashlib
import inspect
import json
import logging
import os
import platform
import plistlib
import re
import socket
import subprocess
import sys

import pexpect
import requests


class FWPM_Object(object):
    """
    This should not be blank.
    """
    def __init__(self, args, logger, master_version):
        """
        This should not be blank.
        """
        self.args = args
        self.logger = logger
        self.master_version = master_version

        self.srp_path = None
        self.fwpwd_path = None
        self.config_options = {}
        self.local_identifier = None
        self.passwords_raw = None
        self.fwpw_managed_string = None
        self.new_password = None
        self.other_password_list = []
        self.current_fwpw_state = False
        self.current_fwpm_hash = None

        self.clean_exit = False
        self.read_config = False
        self.read_keyfile = False
        self.modify_fwpw = False
        self.modify_nvram = False
        self.matching_hashes = False
        self.matching_passwords = False

        self.configuration_path = None

        self.system_version = platform.mac_ver()[0].split(".")

        self.srp_check()
        self.fwpwd_check()

        if self.fwpwd_path:
            self.current_fwpw_state = self.fwpwd_current_state()
        elif self.srp_path:
            self.current_fwpw_state = self.srp_current_state()

        self.injest_config()
        if self.config_options["slack"]["use_slack"]:
            self.slack_optionator()

        self.injest_keyfile()

        self.hash_current_state()
        self.hash_incoming()

        #
        # What if the string isn't a hash?!?
        if (self.current_fwpm_hash == self.fwpw_managed_string) and self.config_options["flags"]["management_string_type"] == 'hash':
            self.matching_hashes = True

        self.master_control()

    def master_control(self):
        """
        This should not be blank.
        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

        if self.current_fwpm_hash == self.fwpw_managed_string:
            if self.logger:
                self.logger.info("Hashes match. No change required.")

        else:
            if self.logger:
                self.logger.info("Hashes DO NOT match. Change required.")

        if self.fwpwd_path:
            self.fwpwd_change()
            self.secure_delete()

        elif self.srp_path:
            self.srp_change()
            self.secure_delete()

        else:
            print("No FW tool found.")
            quit()

        #
        # nvram maintenance
        #
        self.nvram_manager()

        #
        # some kind of post action reporting.
        # handle reboot flag here?
        #
        self.exit_manager()

    def hash_current_state(self):
        """
        This should not be blank.
        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

        existing_keyfile_hash = None
        if self.logger:
            self.logger.info("Checking existing hash.")

        try:
            existing_keyfile_hash_raw = subprocess.check_output(["/usr/sbin/nvram", "-p"]).decode('utf-8')
            existing_keyfile_hash_raw = existing_keyfile_hash_raw.split('\n')
            for item in existing_keyfile_hash_raw:
                if "fwpw-hash" in item:
                    existing_keyfile_hash = item
                else:
                    self.current_fwpm_hash = None

            self.current_fwpm_hash = existing_keyfile_hash.split("\t")[1]

            if self.args.testmode:
                print("Existing hash: %s" % self.current_fwpm_hash)

        except:
            pass

    def hash_incoming(self):
        """
        This should not be blank.
        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

        if self.logger:
            self.logger.info("Checking incoming hash.")

        if self.config_options["flags"]["management_string_type"] == "custom":
            #
            # ?!?!?!?!?!?!?
            #
            self.fwpw_managed_string = self.config_options["flags"]["management_string_type"]

        elif self.config_options["flags"]["management_string_type"] == "hash":

            hashed_key = hashlib.new('sha256')
            # hashed_key.update(self.passwords_raw.encode('utf-8'))

            hashed_key.update(self.new_password.encode('utf-8'))

            for entry in sorted(self.other_password_list):
                hashed_key.update(entry.encode('utf-8'))

            self.fwpw_managed_string = hashed_key.hexdigest()

            # prepend '2:' to denote hash created with v2 of script, will force a password change from v1
            self.fwpw_managed_string = '2:' + self.fwpw_managed_string

        else:
            self.fwpw_managed_string = None

        if self.args.testmode:
            print("Incoming hash: %s" % self.fwpw_managed_string)

    def secure_delete(self):
        """
        attempts to securely delete the keyfile with medium overwrite and zeroing settings
        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

        if self.logger:
            self.logger.info("Deleting keyfile")

        use_srm = bool(os.path.exists("/usr/bin/srm"))

        if self.args.testmode:
            if self.logger:
                self.logger.info("Test mode, keyfile not deleted.")
            return

        if use_srm:
            try:
                subprocess.call(["/usr/bin/srm", "-mz", self.config_options["keyfile"]["path"]])
                if self.logger:
                    self.logger.info("keyfile deleted successfuly.")
            except Exception as exception_message:
                if self.logger:
                    self.logger.critical("Issue with attempt to remove keyfile. %s" % exception_message)
        else:
            try:
                deleted_keyfile = subprocess.call(["/bin/rm", "-Pf", self.config_options["keyfile"]["path"]])
                print("return: %r" % deleted_keyfile)
                if self.logger:
                    self.logger.info("keyfile deleted successfuly.")
            except Exception as exception_message:
                if self.logger:
                    self.logger.critical("Issue with attempt to remove keyfile. %s" % exception_message)

    # is this really needed?
        if os.path.exists(self.config_options["keyfile"]["path"]):
            if self.logger:
                self.logger.critical("Failure to remove keyfile.")
        else:
            if self.logger:
                self.logger.info("Keyfile removed.")
        return

    def injest_config(self):
        """
        attempts to consume and format configuration file
        """

        #               handle parsing errors in cfg?!?

        #               where to handle looking for cfg in specific locations?!?

        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

        try:
            if os.path.exists(self.args.configfile):
                # firmware_password_manager_cfg_v2.5b8.py:434: DeprecationWarning: The SafeConfigParser class has been renamed to ConfigParser in Python 3.2. This alias will be removed in future versions. Use ConfigParser directly instead.
                config = configparser.ConfigParser(allow_no_value=True)
                config.read(self.args.configfile)

                self.config_options["flags"] = {}
                self.config_options["keyfile"] = {}
                self.config_options["logging"] = {}
                self.config_options["slack"] = {}
                self.config_options["os"] = {}
                self.config_options["fwpm"] = {}

                for section in ["flags", "keyfile", "logging", "slack"]:
                    for item in config.options(section):
                        if "use_" in item:
                            try:
                                self.config_options[section][item] = config.getboolean(section, item)
                            except:
                                self.config_options[section][item] = False
                        elif "path" in item:
                            self.config_options[section][item] = config.get(section, item)
                        else:
                            self.config_options[section][item] = config.get(section, item)

                if self.args.testmode:
                    print("Configuration file variables:")
                    for key, value in self.config_options.items():
                        print(key)
                        for sub_key, sub_value in value.items():
                            print("\t%s %r" % (sub_key, sub_value))
            else:
                if self.logger:
                    self.logger.critical("Issue locating configuration file, exiting.")
                sys.exit()
        except Exception as exception_message:
            if self.logger:
                self.logger.critical("Issue reading configuration file, exiting. %s" % exception_message)
            sys.exit()

        self.read_config = True

    def sanity_check(self):
        """
        This should not be blank.
        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

    def srp_check(self):
        """
        full setregproptool support later, if ever.
        """

        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

        if os.path.exists('/usr/local/bin/setregproptool'):
            self.srp_path = '/usr/local/bin/setregproptool'
        elif os.path.exists(os.path.dirname(os.path.abspath(__file__)) + '/setregproptool'):
            self.srp_path = os.path.dirname(os.path.abspath(__file__)) + '/setregproptool'
        else:
            print("SRP #3a")

        if self.logger:
            self.logger.info("SRP path: %s" % self.srp_path)

    def srp_current_state(self):
        """
        full setregproptool support later, if ever.
        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

        try:
            existing_fw_pw = subprocess.call([self.srp_path, "-c"])
            if self.logger:
                self.logger.info("srp says %r" % existing_fw_pw)

            if existing_fw_pw:
                return False
            # it's weird, I know. Blame Apple.
            else:
                return True

        except:
            if self.logger:
                self.logger.info("ERROR srp says %r" % existing_fw_pw)
            return False

#
#         # E:451,15: Undefined variable 'CalledProcessError' (undefined-variable)
#         except CalledProcessError:
#             if self.logger:
#                 self.logger.info("ERROR srp says %r" % existing_fw_pw)
#             return False

    def srp_change(self):
        """
        full setregproptool support later, if ever.
        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])
        print("Using srp tool!")

        print("%r" % self.current_fwpw_state)

    def fwpwd_check(self):
        """
        This should not be blank.
        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

        if os.path.exists('/usr/sbin/firmwarepasswd'):
            self.fwpwd_path = '/usr/sbin/firmwarepasswd'
        else:
            print("FWPWD #2b")

        if self.logger:
            self.logger.info("FWPWD path: %s" % self.fwpwd_path)

    def fwpwd_current_state(self):
        """
        This should not be blank.
        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

        existing_fw_pw = subprocess.check_output([self.fwpwd_path, "-check"])

        # R:484, 8: The if statement can be replaced with 'return bool(test)' (simplifiable-if-statement)
#         return bool('Yes' in existing_fw_pw)

        if b'Yes' in existing_fw_pw:
            return True
        else:
            return False

    def fwpwd_change(self):
        """
        This should not be blank.
        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

        known_current_password = False
        current_password = ''

        # is this really needed?!?
        new_fw_tool_cmd = [self.fwpwd_path, '-verify']

        if self.current_fwpw_state:
            if self.logger:
                self.logger.info("Verifying current FW password")

            for index in reversed(range(len(self.other_password_list))):

                child = pexpect.spawn(' '.join(new_fw_tool_cmd))
                child.expect('Enter password:')

                child.sendline(self.other_password_list[index])
                result = child.expect(['Correct', 'Incorrect'])

                if result == 0:
                    #
                    # correct password, exit loop
                    current_password = self.other_password_list[index]
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
                if not self.config_options["flags"]["use_fwpw"]:
                    if self.logger:
                        self.logger.info("Deleting FW password")

                    new_fw_tool_cmd = [self.fwpwd_path, '-delete']
                    if self.logger:
                        self.logger.info(' '.join(new_fw_tool_cmd))

                    child = pexpect.spawn(' '.join(new_fw_tool_cmd))
                    child.expect('Enter password:')

                    child.sendline(current_password)
                    result = child.expect(['removed', 'incorrect'])

                    if result == 0:
                        #
                        # password accepted, log result and exit
                        if self.logger:
                            self.logger.info("Finished. Password should be removed. Restart required. [%i]" % (index + 1))
                        self.clean_exit = True
                    else:
                        if self.logger:
                            self.logger.critical("Asked to delete, current password not accepted. Exiting.")
#                         secure_delete_keyfile(logger, args, config_options)
                        if self.config_options["slack"]["use_slack"]:
                            self.slack_message("_*" + self.local_identifier + "*_ :no_entry:\n" + "Asked to delete, current password not accepted.", '', 'error')
#                             self.error_bot.send_message("_*" + self.local_identifier + "*_ :no_entry:\n" + "Asked to delete, current password not accepted.")
                        sys.exit(1)

                #
                # Current and new password are identical
                #
                #
                #   WAIT. How (is/would) this possible, clearly the hashes don't match!!! What if they aren't using hashes?
                #
                #
                elif current_password == self.new_password:
                    self.matching_passwords = True
                    self.clean_exit = True

                #
                # Change current firmware password to new password
                else:
                    if self.logger:
                        self.logger.info("Updating FW password")

                    new_fw_tool_cmd = [self.fwpwd_path, '-setpasswd']
                    if self.logger:
                        self.logger.info(' '.join(new_fw_tool_cmd))

                    child = pexpect.spawn(' '.join(new_fw_tool_cmd))

                    result = child.expect('Enter password:')
                    if result == 0:
                        pass
                    else:
                        if self.logger:
                            self.logger.error("bad response from firmwarepasswd. Exiting.")
                        self.secure_delete()
                        if self.config_options["slack"]["use_slack"]:
                            self.slack_message("_*" + self.local_identifier + "*_ :no_entry:\n" + "Bad response from firmwarepasswd.", '', 'error')
                        sys.exit(1)
                    child.sendline(current_password)

                    result = child.expect('Enter new password:')
                    if result == 0:
                        pass
                    else:
                        if self.logger:
                            self.logger.error("bad response from firmwarepasswd. Exiting.")
                        self.secure_delete()
                        if self.config_options["slack"]["use_slack"]:
                            self.slack_message("_*" + self.local_identifier + "*_ :no_entry:\n" + "Bad response from firmwarepasswd.", '', 'error')
                        sys.exit(1)
                    child.sendline(self.new_password)

                    result = child.expect('Re-enter new password:')
                    if result == 0:
                        pass
                    else:
                        if self.logger:
                            self.logger.error("bad response from firmwarepasswd. Exiting.")
                        self.secure_delete()
                        if self.config_options["slack"]["use_slack"]:
                            self.slack_message("_*" + self.local_identifier + "*_ :no_entry:\n" + "Bad response from firmwarepasswd.", '', 'error')
                        sys.exit(1)
                    child.sendline(self.new_password)

                    child.expect(pexpect.EOF)
                    child.close()

                    if self.logger:
                        self.logger.info("Updated FW Password.")
                    self.clean_exit = True

            #
            # Unable to match current password with contents of keyfile
            else:
                if self.logger:
                    self.logger.critical("Current FW password not in keyfile. Quitting.")
                if self.config_options["slack"]["use_slack"]:
                    self.slack_message("_*" + self.local_identifier + "*_ :no_entry:\n" + "Current FW password not in keyfile.", '', 'error')
                self.secure_delete()
                sys.exit(1)

        #
        # No current firmware password, setting it
        else:

            new_fw_tool_cmd = [self.fwpwd_path, '-setpasswd']
            if self.logger:
                self.logger.info(' '.join(new_fw_tool_cmd))

            child = pexpect.spawn(' '.join(new_fw_tool_cmd))

            result = child.expect('Enter new password:')
            print(child.before)
            if result == 0:
                pass
            else:
                if self.logger:
                    self.logger.error("bad response from firmwarepasswd. Exiting.")
                self.secure_delete()
                if self.config_options["slack"]["use_slack"]:
                    self.slack_message("_*" + self.local_identifier + "*_ :no_entry:\n" + "Bad response from firmwarepasswd.", '', 'error')
                sys.exit(1)
            child.sendline(self.new_password)

            result = child.expect('Re-enter new password:')
            if result == 0:
                pass
            else:
                if self.logger:
                    self.logger.error("bad response from firmwarepasswd. Exiting.")
                self.secure_delete()
                if self.config_options["slack"]["use_slack"]:
                    self.slack_message("_*" + self.local_identifier + "*_ :no_entry:\n" + "Bad response from firmwarepasswd.", '', 'error')
                sys.exit(1)
            child.sendline(self.new_password)

            child.expect(pexpect.EOF)
            child.close()

            if self.logger:
                self.logger.info("Added FW Password.")
            self.clean_exit = True

    def slack_optionator(self):
        """

        ip, mac, hostname
        computername
        serial

        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

        if self.verify_network():
            try:
                full_ioreg = subprocess.check_output(['ioreg', '-l']).decode('utf-8')
                serial_number_raw = re.findall('\"IOPlatformSerialNumber\" = \"(.*)\"', full_ioreg)
                serial_number = serial_number_raw[0]
                if self.args.testmode:
                    print("Serial number: %r" % serial_number)

                if self.config_options["slack"]["slack_identifier"].lower() == 'ip' or self.config_options["slack"]["slack_identifier"].lower() == 'mac' or self.config_options["slack"]["slack_identifier"].lower() == 'hostname':
                    processed_device_list = []

                    # Get ordered list of network devices
                    base_network_list = subprocess.check_output(["/usr/sbin/networksetup", "-listnetworkserviceorder"]).decode('utf-8')
                    network_device_list = re.findall(r'\) (.*)\n\(.*Device: (.*)\)', base_network_list)
                    ether_up_list = subprocess.check_output(["/sbin/ifconfig", "-au", "ether"]).decode('utf-8')
                    for device in network_device_list:
                        device_name = device[0]
                        port_name = device[1]
                        try:
                            if self.args.testmode:
                                print(device_name, port_name)

                            if port_name in ether_up_list:
                                device_info_raw = subprocess.check_output(["/sbin/ifconfig", port_name]).decode('utf-8')
                                mac_address = re.findall('ether (.*) \n', device_info_raw)
                                if self.args.testmode:
                                    print("%r" % mac_address)
                                ether_address = re.findall('inet (.*) netmask', device_info_raw)
                                if self.args.testmode:
                                    print("%r" % ether_address)
                                if len(ether_address) and len(mac_address):
                                    processed_device_list.append([device_name, port_name, ether_address[0], mac_address[0]])
                        except Exception as this_exception:
                            print(this_exception)

                    if processed_device_list:
                        if self.logger:
                            self.logger.info("1 or more active IP addresses. Choosing primary.")
                        if self.args.testmode:
                            print("Processed devices: ", processed_device_list)

                        if self.config_options["slack"]["slack_identifier"].lower() == 'ip':
                            self.local_identifier = processed_device_list[0][2] + " (" + processed_device_list[0][0] + ":" + processed_device_list[0][1] + ")"
                        elif self.config_options["slack"]["slack_identifier"].lower() == 'mac':
                            self.local_identifier = processed_device_list[0][3] + " (" + processed_device_list[0][0] + ":" + processed_device_list[0][1] + ")"
                        elif self.config_options["slack"]["slack_identifier"].lower() == 'hostname':
                            try:
                                self.local_identifier = socket.getfqdn()
                            except:
                                if self.logger:
                                    self.logger.error("error discovering hostname info.")
                                self.local_identifier = serial_number

                    else:
                        if self.logger:
                            self.logger.error("error discovering IP info.")
                        self.local_identifier = serial_number

                elif self.config_options["slack"]["slack_identifier"].lower() == 'computername':
                    try:
                        cname_identifier_raw = subprocess.check_output(['/usr/sbin/scutil', '--get', 'ComputerName'])
                        self.local_identifier = cname_identifier_raw.split('\n')[0]
                        if self.logger:
                            self.logger.info("Computername: %r" % self.local_identifier)
                    except:
                        if self.logger:
                            self.logger.info("error discovering computername.")
                        self.local_identifier = serial_number
                elif self.config_options["slack"]["slack_identifier"].lower() == 'serial':
                    self.local_identifier = serial_number
                    if self.logger:
                        self.logger.info("Serial number: %r" % self.local_identifier)
                else:
                    if self.logger:
                        self.logger.info("bad or no identifier flag, defaulting to serial number.")
                    self.local_identifier = serial_number

                if self.args.testmode:
                    print("Local identifier: %r" % self.local_identifier)

            except Exception as this_exception:
                print(this_exception)
                self.config_options["slack"]["use_slack"] = False
        else:
            self.config_options["slack"]["use_slack"] = False
            if self.logger:
                self.logger.info("No network detected.")

    def slack_message(self, message, icon, type):
        """
        This should not be blank.
        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

        slack_info_channel = False
        slack_error_channel = False

        if self.config_options["slack"]["use_slack"] and self.config_options["slack"]["slack_info_url"]:
            slack_info_channel = True

        if self.config_options["slack"]["use_slack"] and self.config_options["slack"]["slack_error_url"]:
            slack_error_channel = True

        if slack_error_channel and type == 'error':
            slack_url = self.config_options["slack"]["slack_error_url"]
        elif slack_info_channel:
            slack_url = self.config_options["slack"]["slack_info_url"]
        else:
            return

        payload = {'text': message, 'username': 'FWPM ' + self.master_version, 'icon_emoji': ':key:'}

        response = requests.post(slack_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})

        self.logger.info('Response: ' + str(response.text))
        self.logger.info('Response code: ' + str(response.status_code))

    def reboot_exit(self):
        """
        This should not be blank.
        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

    def injest_keyfile(self):
        """
        This should not be blank.
        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

        path_to_keyfile_exists = os.path.exists(self.config_options["keyfile"]["path"])

        if not path_to_keyfile_exists:
            if self.logger:
                self.logger.critical("%r does not exist. Exiting." % self.config_options["keyfile"]["path"])
            if self.config_options["slack"]["use_slack"]:
                self.slack_message("_*" + self.local_identifier + "*_ :no_entry:\n" + "Keyfile does not exist.", '', 'error')
            sys.exit(2)

        if self.logger:
            self.logger.info("Reading password file")

        if self.config_options["keyfile"]["use_obfuscation"]:
            #
            # unobfuscate plist
            if self.logger:
                self.logger.info("Reading plist")
            passwords = []
            if "plist" in self.config_options["keyfile"]["path"]:
                try:
                    keyfile_plist = plistlib.readPlist(self.config_options["keyfile"]["path"])
                    content_raw = keyfile_plist["data"]
                except:
                    if self.logger:
                        self.logger.critical("Error reading plist. Exiting.")
                    if self.config_options["slack"]["use_slack"]:
                        self.slack_message("_*" + self.local_identifier + "*_ :no_entry:\n" + "Error reading plist.", '', 'error')
                    sys.exit(1)

            else:
                try:
                    with open(self.config_options["keyfile"]["path"], 'r') as reader:
                        content_raw = reader.read()
                except:
                    if self.logger:
                        self.logger.critical("Error reading plist. Exiting.")
                    if self.config_options["slack"]["use_slack"]:
                        self.slack_message("_*" + self.local_identifier + "*_ :no_entry:\n" + "Error reading plist.", '', 'error')
                    sys.exit(1)

            content_raw = base64.b64decode(content_raw)
            content_raw = content_raw.decode('utf-8').split(",")
            content_raw = [x for x in content_raw if x]

            output_string = ""
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
                    output_string = "#" + commented.decode('utf-8') + ":" + pword.decode('utf-8')
                    passwords.append(output_string)

                else:
                    uncommented = base64.b64decode(label)
                    output_string = uncommented.decode('utf-8') + ":" + pword.decode('utf-8')
                    passwords.append(output_string)

        else:
            #
            #  read keyfile
            if self.logger:
                self.logger.info("Reading plain text")

            try:
                with open(self.config_options["keyfile"]["path"], "r") as keyfile:
                    self.passwords_raw = keyfile.read()

                passwords = self.passwords_raw.splitlines()

            except:
                if self.logger:
                    self.logger.critical("Error reading keyfile. Exiting.")
                if self.config_options["slack"]["use_slack"]:
                    self.slack_message("_*" + self.local_identifier + "*_ :no_entry:\n" + "Error reading keyfile.", '', 'error')
                sys.exit(1)

            if self.logger:
                self.logger.info("Closed password file")

            # new_password = None
            # other_password_list = []

        #
        # parse data from keyfile and build list of passwords
        for entry in passwords:
            try:
                key, value = entry.split(":", 1)
            except Exception as this_exception:
                if self.logger:
                    self.logger.critical("Malformed keyfile, key:value format required. %r. Quitting." % this_exception)
                self.secure_delete()
                if self.config_options["slack"]["use_slack"]:
                    self.slack_message("_*" + self.local_identifier + "*_ :no_entry:\n" + "Malformed keyfile.", '', 'error')
                sys.exit(1)

            if key.lower() == 'new':
                if self.new_password is not None:
                    if self.logger:
                        self.logger.critical("Malformed keyfile, multiple new keys. Quitting.")
                    self.secure_delete()
                    if self.config_options["slack"]["use_slack"]:
                        self.slack_message("_*" + self.local_identifier + "*_ :no_entry:\n" + "Malformed keyfile.", '', 'error')
                    sys.exit(1)
                else:
                    self.new_password = value
                    self.other_password_list.append(value)
            else:
                self.other_password_list.append(value)

        if self.logger:
            self.logger.info("Sanity checking password file contents")

        if self.new_password is None and self.config_options["flags"]["use_fwpw"]:
            if self.logger:
                self.logger.critical("Malformed keyfile, no \'new\' key. Quitting.")
            self.secure_delete()
            if self.config_options["slack"]["use_slack"]:
                self.slack_message("_*" + self.local_identifier + "*_ :no_entry:\n" + "Malformed keyfile.", '', 'error')
            sys.exit(1)

        self.read_keyfile = True

        try:
            self.other_password_list.remove(self.new_password)
        except:
            pass

    def nvram_manager(self):
        """
        This should not be blank.
        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

        if self.clean_exit:
            if not self.config_options["flags"]["use_fwpw"]:
                try:
                    subprocess.call(["/usr/sbin/nvram", "-d", "fwpw-hash"])
                    if self.logger:
                        self.logger.info("nvram entry pruned.")
                    if self.config_options["slack"]["use_slack"]:
                        self.slack_message("_*" + self.local_identifier + "*_ :unlock:\n" + "FWPW and nvram entry removed.", '', 'info')
                        #
                        # Should we return here?
                        #
                except Exception as exception_message:
                    if self.logger:
                        self.logger.warning("nvram reported error attempting to remove hash. Exiting. %s" % exception_message)
                    #
                    # Slack?
                    #
                    sys.exit(1)

            if self.config_options["flags"]["management_string_type"] == "None":
                try:
                    # ?
                    # existing_keyfile_hash = subprocess.check_output(["/usr/sbin/nvram", "fwpw-hash"])
                    try:
                        subprocess.call(["/usr/sbin/nvram", "-d", "fwpw-hash"])
                        if self.logger:
                            self.logger.info("nvram entry pruned.")
                        if self.config_options["slack"]["use_slack"]:
                            self.slack_message("_*" + self.local_identifier + "*_ :closed_lock_with_key:\n" + "FWPW updated.", '', 'info')
                    except Exception as exception_message:
                        if self.logger:
                            self.logger.warning("nvram reported error attempting to remove hash. Exiting. %s" % exception_message)
                        sys.exit(1)
                except:
                    # assuming hash doesn't exist.
                    if self.logger:
                        self.logger.info("Assuming nvram entry doesn't exist.")
                    if self.config_options["slack"]["use_slack"]:
                        self.slack_message("_*" + self.local_identifier + "*_ :closed_lock_with_key:\n" + "FWPW updated.", '', 'info')

            elif self.config_options["flags"]["management_string_type"] == "custom" or self.config_options["flags"]["management_string_type"] == "hash":
                if self.matching_hashes:
                    if self.matching_passwords:
                        if self.logger:
                            self.logger.info("Hashes and Passwords match. No changes needed.")
                        if self.config_options["slack"]["use_slack"]:
                            self.slack_message("_*" + self.local_identifier + "*_  :white_check_mark::white_check_mark:\n" + "FWPM hashes and FW passwords match.", '', 'info')
                    else:
                        if self.logger:
                            self.logger.info("Hashes match, password modified.")
                        if self.config_options["slack"]["use_slack"]:
                            self.slack_message("_*" + self.local_identifier + "*_  :white_check_mark::heavy_exclamation_mark:\n" + "FWPM hashes and FW passwords match.", '', 'info')
                else:
                    try:
                        subprocess.call(["/usr/sbin/nvram", "fwpw-hash=" + self.fwpw_managed_string])
                        if self.logger:
                            self.logger.info("nvram modified.")
                    except Exception as exception_message:
                        if self.logger:
                            self.logger.warning("nvram modification failed. nvram reported error. %s" % exception_message)
                            #
                            # slack error message?
                            #
                        sys.exit(1)

                    if self.matching_passwords:
                        if self.logger:
                            self.logger.info("Hash mismatch, Passwords match. Correcting hash.")
                        if self.config_options["slack"]["use_slack"]:
                            self.slack_message("_*" + self.local_identifier + "*_ :heavy_exclamation_mark: :white_check_mark:\n" + "Hash mismatch, Passwords match. Correcting hash.", '', 'info')
                    else:
                        if self.config_options["slack"]["use_slack"]:
                            self.slack_message("_*" + self.local_identifier + "*_ :closed_lock_with_key:\n" + "FWPW and hash updated.", '', 'info')

        else:
            if self.logger:
                self.logger.critical("An error occured. Failed to modify firmware password.")
            if self.config_options["slack"]["use_slack"]:
                self.slack_message("_*" + self.local_identifier + "*_ :no_entry:\n" + "An error occured. Failed to modify firmware password.", '', 'error')
            sys.exit(1)

    def exit_manager(self):
        """
        This should not be blank.
        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

        #
        #   check the new booleans, etc to find out what we accomplished...
        #

        #         self.clean_exit = False
        #
        #         self.read_config = False
        #         self.read_keyfile = False
        #         self.modify_fwpw = False
        #         self.modify_nvram = False
        #

        if self.config_options["flags"]["use_reboot_on_exit"]:
            if self.args.testmode:
                if self.logger:
                    self.logger.info("Test mode, cancelling reboot.")
            else:
                if self.logger:
                    self.logger.warning("Normal completion. Rebooting.")
                os.system('reboot')
        else:
            if self.logger:
                self.logger.info("FWPM exiting normally.")
            sys.exit(0)

    def verify_network(self):
        """
        Host: 8.8.8.8 (google-public-dns-a.google.com)
        OpenPort: 53/tcp
        Service: domain (DNS/TCP)
        """

        try:
            _ = requests.get("https://8.8.8.8", timeout=3)
            return True
        except requests.ConnectionError as exception_message:
            print(exception_message)
        return False


def main():
    """
    This should not be blank.
    """
    master_version = "2.5"

    logo = """
         /_ _/ /_ _/   University of Utah
          _/    _/    Marriott Library
         _/    _/    Mac Group
        _/    _/   https://apple.lib.utah.edu/
         _/_/    https://github.com/univ-of-utah-marriott-library-apple


        """
    desc = "Manages the firmware password on Apple Macintosh computers."

    #
    # require root to run.
    if os.geteuid():
        print("Must be root to run script.")
        sys.exit(2)

    #
    # parse option definitions
    parser = argparse.ArgumentParser(description=logo+desc, formatter_class=RawTextHelpFormatter)

    #
    # required, mutually exclusive commands
    prime_group = parser.add_argument_group('Required management settings', 'Choosing one of these options is required to run FWPM. They tell FWPM how you want to manage the firmware password.')
    subprime = prime_group.add_mutually_exclusive_group(required=True)
    subprime.add_argument('-c', '--configfile', help='Read configuration file')

    parser.add_argument('-b', '--reboot', action="store_true", default=False, help='Reboots the computer after the script completes successfully.')
    parser.add_argument('-t', '--testmode', action="store_true", default=False, help='Test mode. Verbose logging, will not delete keyfile.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + master_version)

    args = parser.parse_args()

    if args.testmode:
        print(args)

    #
    # Open log file
    try:
        log_path = '/var/log/' + 'FWPW_Manager_' + master_version
        logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        logger = logging.getLogger(__name__)
        logger.info("Running Firmware Password Manager " + master_version)
    except:
        logger = None

    FWPM_Object(args, logger, master_version)


if __name__ == '__main__':
    main()

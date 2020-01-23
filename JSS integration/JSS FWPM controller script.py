#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Script to remotely control and configure firmware password manager.
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

# FWPM_control.py ##############################################################
#
#
#
#    0.8.0  2019.11.13      Complete rewrite. FWPM built with pyinstall and kept
#                           on client machines, Control script holds keylist and
#                           config file, writes files and launches FWPM.  tjm
#
#    1.0.0  2020.01.23      Initial public release. tjm
#
################################################################################

from __future__ import division
from __future__ import print_function
import base64
import logging
import inspect
import subprocess

__version__ = '1.0'

KEYFILE = {
    'previous': ["oneOldPassword", "AnotherPasswordWeUsed"],
    'new': "myNewFWPW!"
}

FWPM_CONFIG = {
    'flags': {
        'use_fwpw': True,
        'management_string_type': 'hash',
        'custom_string': '',
        'use_reboot_on_exit': False,
        'path_to_fw_tool': '',
        'use_test_mode': False,
    },

    'keyfile': {
        'path': '/tmp/current_fwpw.txt',
        'use_obfuscation': True,
    },

    'logging': {
        'use_logging': True,
        'log_path': '/var/log/fwpm_controller.log',
    },

    'slack': {
        'use_slack': True,
        'slack_identifier': 'hostname',

        'slack_info_url': 'https://hooks.slack.com/services/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',
        'slack_error_url': 'https://hooks.slack.com/services/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',
    }
}


def prepare_keyfile(logger, cleartext):
    """
    Convert keyfile into format FWPM expects and obfuscate results.
    """
    if FWPM_CONFIG['logging']['use_logging']:
        logger.info("%s: activated" % inspect.stack()[0][3])

    obfuscated_string = ""
    sanity_check_new = False
    sanity_check_previous = False

    # sanity check cleartext!
    logger.info("sanity check new.")
    if not isinstance(cleartext['new'], str):
        logger.critical("New password improperly defined.")
        sanity_check_new = False
    else:
        sanity_check_new = True

    logger.info("sanity check previous.")
    if len(cleartext['previous']) <= 1:
        logger.critical("No previous password defined.")
        sanity_check_previous = False
    else:
        sanity_check_previous = True

    if not sanity_check_new or not sanity_check_previous:
        logger.critical("sanity check failure.")
        return None
    else:
        logger.info("Sanity check successful.")

    encoded_comment = base64.b64encode('old'.encode('utf-8'))

    for item in cleartext['previous']:
        tmp_item = base64.b64encode(item.encode('utf-8'))
        tmp_string = '#'.encode('utf-8') + encoded_comment + ':'.encode('utf-8') + tmp_item + ','.encode('utf-8')
        obfuscated_string = obfuscated_string + tmp_string.decode('utf-8')

    tmp_item = base64.b64encode(cleartext['new'].encode('utf-8'))
    tmp_string = base64.b64encode('new'.encode('utf-8')) + ':'.encode('utf-8') + tmp_item
    obfuscated_string += str(tmp_string.decode('utf-8'))

    return base64.b64encode(obfuscated_string.encode('utf-8'))


def main():
    """
    This should not be blank.
    """

    if FWPM_CONFIG['logging']['use_logging']:
        logging.basicConfig(filename=FWPM_CONFIG['logging']['log_path'], level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        logger = logging.getLogger(__name__)

        logger.info("fwpm controller launched.")
        logger.info("fwpm controller version {}".format(__version__))

    configuraton_file_path = '/tmp/cfg.cfg'

    obfuscated_text = prepare_keyfile(logger, KEYFILE)

    if obfuscated_text is None:
            logger.critical("Exiting on sanity check failure.")
            quit()

    with open(FWPM_CONFIG['keyfile']['path'], 'w') as output_file:
        output_file.write((obfuscated_text.decode('utf-8')))

    with open(configuraton_file_path, 'w') as writer:
        for k in FWPM_CONFIG:
            writer.write("[" + k + "]" + "\n")
            for k2 in FWPM_CONFIG[k]:
                writer.write(k2 + ": " + str(FWPM_CONFIG[k][k2]) + "\n")

    # launch fwpm
    logger.info("launching fwpm.")

    try:
        _ = subprocess.check_output(["/usr/local/sbin/firmware_password_manager", "-c", configuraton_file_path])
    except Exception as exception_message:
        print(exception_message)
        logger.critical(exception_message)



if __name__ == '__main__':
    main()

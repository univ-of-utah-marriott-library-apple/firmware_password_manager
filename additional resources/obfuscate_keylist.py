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

# obfuscate_keylist.py #########################################################
#
# A Python script to help obfuscate a plain text keyfile.
#
#
#	 1.0.0	  2016.03.07	initial release. tjm
#
################################################################################

# notes: #######################################################################
#
#
################################################################################

import base64
import plistlib
import argparse
import os
import sys

def main():
    #
    # parse option definitions
    parser = argparse.ArgumentParser(description='Obfuscate plain text keyfile to base64-encoded plist.')
    parser.add_argument('-s', '--source', help='Set path to source keyfile', required=True)
    parser.add_argument('-d', '--destination', help='Set path to save obfuscated keyfile', required=True)
    parser.add_argument('-t', '--testmode', action="store_true", default=False, help='Test mode, verbose output.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0.0')
    args = parser.parse_args()

    if args.testmode:
        print "Source file     : %s" % args.source
        print "Destination file: %s\n" % args.destination


    obfuscated = []
    unobfuscated_string = ''
    obfuscated_string = ''
    has_new_label = False

    if os.path.exists(args.destination):
        continue_choice = False
        continue_entry = raw_input("Destination file \"%s\" already exists, Continue? [yN]:" % args.destination)
        while not continue_choice:
            if continue_entry is "n" or continue_entry is "N" or continue_entry is "":
                print "Exiting."
                sys.exit(1)
            elif continue_entry is "y" or continue_entry is "Y":
                break
            else:
                continue_entry = raw_input("Invalid entry. Destination file \"%s\" already exists, Continue? [yN]:" % args.destination)

    try:
        tmp_file = open(args.source)
        content_raw = tmp_file.read()
        tmp_file.close()
    except IOError:
        print "%s not found. Exiting." % args.source
        sys.exit(1)
    except Exception as e:
        print "Unknown error [%s]. Exiting." % e
        sys.exit(1)

    content_raw = content_raw.split("\n")
    content_raw = [x for x in content_raw if x]

    if args.testmode:
        print "plain text: \n%s\n" % content_raw

    for x in content_raw:
        label, pword = x.split(':')

        if label.lower() == 'new':
            if has_new_label:
                print "ERROR. Keylist has multiple \'new\' labels and is not valid. Exiting."
                sys.exit(1)
            else:
                has_new_label = True

        if args.testmode:
            print "entry     : %r, %r, %r" % (label, pword, has_new_label)
        pword = base64.b64encode(pword)
        try:
            commented = label.split('#')[1]
            commented = base64.b64encode(commented)
            is_commented = True
        except:
            is_commented = False

        if is_commented:
            output_string = "#"+commented+":"+pword
        else:
            output_string = label+":"+pword
        unobfuscated_string = unobfuscated_string + output_string + ","
        obfuscated.append(output_string)
        if args.testmode:
            print "obfuscated: %s" % (output_string)

    if not has_new_label:
        print "ERROR. Keylist has no \'new\' label and is not valid. Exiting."
        sys.exit(1)

    pl = dict(
        data = base64.b64encode(unobfuscated_string)
    )

    if args.testmode:
        print "\nplist entry: \n%s\n" % pl

    try:
        plistlib.writePlist(pl, args.destination)
    except Exception as e:
        print "Unknown error [%s]. Exiting." % e
        sys.exit(1)

    if args.testmode:
        print "%s created. Exiting." % args.destination


    # end code here.
if __name__ == '__main__':
    main()

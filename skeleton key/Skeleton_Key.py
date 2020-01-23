#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Skeleton Key
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

# skeleton_key.py #################################################
#
# A Python Tk application to set/unset the firmware password.
#
#
#    0.1.0  2017.04.13      Initial build. tjm
#    0.2.0  2017.05.04      single pane. tjm
#    1.0.0  2020.01.22      Initial release,
#                           JAMF and Slack integration,
#                           hash generation, reading config file. tjm
#
################################################################################

# notes: #######################################################################
#
# sudo /usr/local/bin/pyinstaller --onefile Skeleton_Key.spec
#
#
#
#
################################################################################

from __future__ import division
from __future__ import print_function
import base64
import ConfigParser
import hashlib
import inspect
import json
import os
import platform
import plistlib
import pwd
import re
import socket
import subprocess
import sys
import tkFileDialog
import tkSimpleDialog
import ttk
from Tkinter import Tk, N, E, S, W, StringVar, IntVar, PhotoImage, HORIZONTAL
import logging
import pexpect
import requests

try:
    import mount_shares_better as msb
except:
    pass


class SinglePane(object):
    """
    Load keys, generate hashes, toggle fwpw
    """

    def __init__(self, root, logger, admin_password, fwpw_status, master_version):
        """
        Initialize object and variables
        """

        self.logger = logger
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        self.root = root
        self.root.title("Skeleton Key " + master_version)

        self.logo = '''\
        R0lGODlhWAJRAPcAAAEAAAgHBwwLCxAPDxQTExgXFxwcHCEfHyYlJSgnJywsLD0nJzItLTY2Njg3
        Nzw8PF4dHGMcG24cGnIdG1QgH18gH0EmJkgpKEA/P1glJEJCQkhHR0tLS1BPT1NSUlhXV1lZWWFf
        X3NcXGRjY2hnZ2xra3Bvb3ppaXRzc3h2d318fJcAAJsAAp8AC4obGJ4dGKAADaEAFKQAGqceGbAf
        GqUhHqwhHrQhHL4hG6cEIqgEI6cKI6kNJqkOKKkQJ6sWK6sYLKwbMJgsKpw0MpI0M6UlIqEoJaEs
        KqolIqMxL68lNLEpOaE1M6E5N6M+PbMwPp9AP7QyQrc8SZ1DQpxLSplHRp5ZWKJDQqFLSrpBTaFQ
        T79OWKVZWIBuboB+fop4eKxraqdnZql6ebN+fbJ2dcNXX8JXYcRcZsZeacdjbshmb8hmcM92freA
        f896gnKBgISEhIyMjIiGh5OTk5ycnJiWlpCJibuMi6Cfn76enqyJiaSjo6inp6qqqrCvr7+trbS0
        tLi3t7m5ubm3uNODiteOltiPlsSZmNeRltiRltqUmtqYncCMi+KboMSkpMqqqt+mqt6ho8C/v8q6
        uti7u+Cnq+GqruuiqeOusuSxs+K5vMTExMjHx8zMzN/GxtDPz9/Jyc/Q0NLS0tjX19zc3O3KzOjH
        yO/P0eTV1e/R0+Pa2u/e3vDR0/Lc3fTe4N/h4OTk5Orl5erq6unn6PPt7vjt7vT09Pr29/////f4
        +Pnu8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAAAAAAALAAAAABYAlEA
        AAj+AHEJHEiwoMGDCBMqXMiwocOHECNKnEixosWLGDNq3Mixo8ePIEOKFAlLkBwQGho00ABCjiBY
        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
        5T53utfd7nfHe971jouAAAA7
        '''

        self.open_lock_icon = '''\
        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
        By988Hf0cVFAADs=
        '''

        self.closed_lock_icon = '''\
        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
        '''

        self.key_icon = '''\
        R0lGODlhMAAwAPcAAAABAAkFAgQLBg0IAwwNCxMMBQwQCBgRBhEVChQYCxsYChISEhwcHCIXCSUb
        CyseCzgVBC8hDDEiDTgnDz0tEiYmJi0tLTQ0NDs7O0YdB00iCVYmC1wqC0o1FFY7Flg9F1k/GGsx
        DlxBGWBDGmZJHGlNHm5QHnRRH0RAOnVUIXpVIEVFRUxMTFxZVlxcXGJiYmpqanFuZHNzc3l5eZNG
        FaVQGINbI4NhJo1jJpJmJ5BnKJVrKZ5sKbVuJ6N1LbJyKrl2K7B5L7J9ML5/MchiHsN8LPN3JPl8
        JrSBMryDMr+MNcyALtWDLsGFM8mNNtWWOtSYOtibPP+BJ/+FKP+JKv+SLeOMMuyPM+GcPO+cOueh
        PuyiPvGjPqqbeu2mQPOnQPSqQfqtQvGzRP60Rf+5R/i3SPe8SP69Sf/ES//LTv/RT//RUf/cVP/q
        Wf/0Xf/udIWFhYiIiJKSkqWlpKysrLOzs7u7u83EkP/0nMnDp8XFxcvLy9/f3+Tk5Ovr6/Xv6PX1
        9Pr6+QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAAIIALAAAAAAwADAA
        AAj+AAUJHEiwoMGDCBMqXMiwocOHECNKnEixosWLGDNq3MixY0Y6L1asgKHHo8IZAABI+ODBAYAF
        dEwW9FMBAA4uZNCsQRNGBAAYMgUCYqBAyxoyY9BgGWKmDQ8AcYKyKCAGDZgwaEikBHDDTQ4Ae0zu
        AeAEDRcwaHYACEFkAwAhbB4A9eiCAhoxXMaQEZChypQqEBCw0UGgJEdABHSkAXN1DAAOVYxU0SBA
        DRQAcjqOdXKGMdoUAGocoQHAhpotAaJyHPukM+MxZShs9YAGzeXMHPkASGKV8ZekQkzwTuoDQJ2O
        gQyQ6O0bq5reaDqsCNQRDw8erj1r54ImCoCYHLv+YKn9Rft2NGQcXOjogixzNGfCeCazZssDAn44
        sgDQowoYMfKp0ERttYVhAwAM5LfRfkBQccUZtY3hgAATePBBBwUAMAMgHK0AQBFUZIGGEx6o8AYg
        e8ThggszzKHgRisIAGIWEJ4AwAV/BDUQBggsEWIZaKmAgY47EgDiFmiUUQYbJqxHpAUIMBHiGV5g
        MYYQP+kISAUJWEGFF2ngAEAAGbqgZQUGXPEjGiMwMIccc+jYxwUJqLnFGWOsAYKTRNIBQINedIak
        BxYQKVAdAPyAJxgRjAkACoYKgigSanQWQAx92NFHpIgGAd8XANwR6UCIHuCAAwcAkMeoAvUBxwsU
        MswwwwubsmrrrbjmquuuvPbKUUAAOw==
        '''

        self.balloon_icon = '''\
        R0lGODlhMAAwAPejAAAAAAICAgMDAwQEBAUFBQgICAkJCQoKCgsLCwwMDA0NDQ8PDxAQEBERERQU
        FBUVFRYWFhgYGBsbGx0dHR4eHh8fHyEhISMjIyUlJSYmJicnJygoKCsrKy0tLTAwMDIyMjMzMzQ0
        NDc3Nzg4ODo6Ojw8PD09PT8/P0JCQkdHR0hISEtLS0xMTE1NTU9PT1BQUFFRUVJSUlRUVFVVVVZW
        VldXV1lZWVpaWltbW11dXV9fX2BgYGFhYWJiYmVlZWZmZmhoaGlpaWpqamtra21tbW5ubm9vb3Jy
        cnNzc3Z2dnh4eHt7e3x8fH5+fn9/f4CAgIKCgoODg4SEhIaGhoyMjI2NjY6Ojo+Pj5CQkJSUlJaW
        lpeXl5mZmZubm52dnZ6enqGhoaKioqOjo6SkpKenp6mpqaqqqqurq6ysrK2tra6urq+vr7CwsLGx
        sbOzs7S0tLa2tre3t7m5ubu7u7y8vL29vb+/v8HBwcLCwsPDw8TExMXFxcbGxsnJycrKysvLy83N
        zc/Pz9DQ0NLS0tTU1NXV1djY2NnZ2dra2tvb29zc3N/f3+Dg4OHh4ePj4+fn5+jo6Onp6erq6uzs
        7O3t7e/v7/Dw8PHx8fLy8vPz8/T09Pb29vf39/n5+fr6+vv7+/z8/P39/f7+/v///wAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAAKQALAAAAAAwADAA
        AAj+AEkJHEiwoMGDCBMqXMiwocOHECNKnEiRVKAvVbr4qTgRlBscCgCINCAjTSeODvVUIMDji59D
        gML8OBBBDsqFUQDsqDSqp89RmoQASHITIRYAYX4q7bkGgJOiBeEAELO0ahsAZaAO3MCjqtcjETZp
        VQPgkdeqmBqI0YrDx1mvRlYYyuIFEcUyHhgA+PK26hkAASYsAACBDMRNIQD84GOoU9+lmvpACuXp
        ERMANBx+ytBh0ePPPu8AMNLQRgRKoFOPmgNgo8JFAPKoVt3iRiOFVCh4mp0azAMvCmG45Q1aUAAp
        ClEgIQ4akIApCn2kYP55i4S1Ca9Got63RJFLCy3+POF+9guARAzHACBDfmkaANAbOtnbvuefFQCa
        QJwhpP6kABcYEpEOQdQ3ygpFSKSECAYO8YJEdAAwSH0q+DCRBle0BxsaEy1RgFncdYFBRR/k8Jko
        opxFSEWEELDDYzw08IdPfXxQgBCQoHTHACYg4tUiKmggAwBbjOIFABv0AIEDe6D0CAkA+JBGIZZY
        YkgbQADwASOkxJGJIgBY4dMQGhQFRw0IACCAAAAUAMMbBTEBwk+NAMAGVJzgAQYYdmRyUAw9/JRJ
        AlxoxdAVAUASGgCFGLoQKBWwgEgldUSQAymPmCGJowg1koFIALhAiiVpRoAJpwgNsoYjAhHRwigb
        J0CBKkNOjCAIB1rMyhALANig66/ABitsUQEBADs=
        '''

        self.shield_icon = '''\
        R0lGODlhMAAwAPcAAAEAAAwBAQAGCAALDQsLCxIAABgAAAAPEgAQEwQdHhQUFB0dHSQBASwBADIB
        AD0OBxQsLRMjJQ8wMRsyNRk1OCQkJCsrKzAvLjAwLyUyNDMzMzg3Nz08PEQDAFwKBlULCFcGA08U
        DVEUDVoXDmMIA2sKBXANCHQUD34RDGYbEXwmGiZCRjpRUkRDQ09OTkpcXFNTUlhYV1tbWmBgX0Rl
        Zk9lZlJgYVJsbllzdGRkY2pqamJzdXJxcHV6enx7e4gTD44XEpMZEqojHLkkHZYuIYwxI5czJaU6
        K8sjHs4nIc0qI9knIdIvJ9ovJ9EvKNIwJ9MyKtwxKdg9Mu0sJuQzK+s1LPM3Lfg3Lvc4Lvs4L/87
        MbdCM8pMO99JPOBNPt9WRORUQ+dYRupaR+xdSfVSQ/9WRfVdSfxbSe5iTfRgTPxiTf9mUf9rVP9v
        WP9yWnaAgXyLjYOEg4yLioCSk4uRkYSYmJSTk5ubm5SdnZqjpJ2oqKSkpKOop6mpp6eqqqurq6ez
        srOzs7O9vb69vcC/v77Dw8PEw8jGxsnIx8vLytHQz9TU09jW1dvZ19zc3ODf3t/g3uPj4+rn5uvp
        5+rq6fDv7vTz8/7+/gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAAJgALAAAAAAwADAA
        AAj+ADEJHEiwoMGDCBMqXMiwocOHECNKnEixosWLGA06GmRHR4wWLVzkkBNokaWMBxfFqQCAQAUO
        LmTI+IhBAQAFOQahFLjIBYAKOghZquRokdFFjihZUqkBgIU/Ge847XPJUqEdEw4A2ArgAAQbgChd
        6glAxkU7AHRcutRjwFYHKYoQAYKChAOuLyBd+gOgRUVHAHJcOoQAwAguatawaVNmipXHVJSY2Brn
        UiAAdijqWDAYAIMvbNaYESNmzJgnTFJHoZKFigcAPS7JqECRQ4xLEQqEFhNmDGkxo1GnTk1FCwgA
        kezQnhjDRSIARNiEKU3dNBopqYUziQxAUBwNFH3+cDgEwAib3+jHeFEyPDuVId1n+J3Ix4IiBCnO
        oxeDxkuS9kygZkUQABTSgg4UIRLAIhN0oB96aITxH4BMXFHCAIdYcAdFjwAwyA0NrOEbdaT1x95w
        AnYggSIEHELRJQrQAQcAaoy23xhpSMEeagIycAMhADxSUQwx5AEAYvvxFwaFqwEwhxwKXFKRHRaQ
        p8KDpPmW3ZZWCAEAHzGYVdEiACSyggNYjtFfEk4EOJxxAySyQB8WWRLAHXPQaONvY0iRhHZMWFEA
        DeQ5cpEMOZB3hHQQjgGFE5AqwZ0eciyA0SAEODIBmjei8egTkGrxmiMcxIHRJQTcYWQYavhmWp/4
        EzIRRRUA4EBeJBnpoAElAqTQxnT8dcFmak5oAQQAi+iK0nOHzCiGGtP5xqOsVgTAgiQB5LETBy1c
        AoAIbowxHRqnpabFCcj5oMBJKJGHCB4AbPGrdX5SwQQANlgiQGY7YdKCBZdkAIAZa4SBhrCsMTCA
        bFH2iwlgd3jbABtsrNeEFh+USSZUDmMSBwCVkBeCG2QscS4AdFxSwXwdY7IAwHwA8MAZosImGwCU
        tMwTALddFgADAFT2MZ06C9RHWmNBkEAgl6DlQ9EEocVDVZFcIhWCUEfNsyWX+JBW1gb9QYAGLQQN
        9kGRcGBBIme37fbbcMct99xQBwQAOw==
        '''

        self.double_exclamation_icon = '''\
        R0lGODlhKAAoAPcAAJcbD5QbEZkcEL4cDq0fE50lGZ8pHaAqHrQhFLsiFbYmGpguJZoyKpk4MMId
        D8EeEMQkFsslF8onGMIoG84oGdUpGtwrGtEwH+MtHOouHPEtGuwwHvAxHsYuIcgzJcs3KdQyItk3
        KN87Kt0+MO80IOM/LvE2IfQ4I8pAM8pGOs1LP9RCNd9DNNVGONlLPeRBMKBQSrVTS61eV7peValo
        Y8FTSc1XTN9TRNRWSd1WStdbTs1bUNleUvJbR9ZnXd9mWuBqXvFpWvhwW9FsY9hsYdtxZ9N0a9l/
        dut1Zut2aOt6bPp3Yvl8aOF8cseEftCEfd2FfeOCePGEeLmGgsiGgdmHgNyLg9CPiN2TjN6cleGN
        heuKgOWUjOOZkuqbkvSclN63tNW4ttm/veimoOOqpeurpeavquyxq+i1sO67tuS9uu2+uu3DvvnE
        v9/KyOHEwezGw+7JxfDHw/HLx/zKxPzPyfLRzfzRzPLV0vPZ1/Xc2v3b2O/k4/Pm5fjm5P7o5vbt
        7Pnt6/bw7/bx8Pvz8vz49/36+gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEAAIcALAAAAAAoACgA
        AAj+AA8JHEiwoMGDCBMqXMiwocOHECNKnAhxT5s6dO7cqVPnTsaChuhk1MiRIx0/DL/0kMKkpUsh
        UgoWCuKy5pIgbRh6wWDCBAkTG06c4BDF4A0THIAOFXrDDsM0IjRoyEA1w1QvBoFsmFp1KhCUC+3k
        IJGBhIYNGzhgOGMwSlq0GbZmiGKIoZ8fZami3YAhjkEue/dy2MClIaEmGOJmwIC2Qh6DZRhXjYuh
        jEMuGMiSSEwiRCCDbCxQJUvVAhuHY0RjSMzYxcE8F0iojnsBj8PQm1cn5nEQEIgNGUSLBvG5oZ0K
        unUXOWioRWnRGVrUbejnQnIMFrQg1IE9uY6Hhkb+YLdgAXsXhER0l7dABCIO8t0roEEIZf16KBB9
        kIdfAQ7CLhXsZ0EF5z0ERYAVIFeBHgiZEeB+FZgBERYIBugBIQjBgSB5FPj3EBkVVoBDQnhIMGCA
        ETz2kBoJtrhDQoB4cGIFHgACUYktUmCEQim0WEEKEfnhQY5WKLSDjy9CZAgKM2ahEBE+thfRDAEc
        UIAAaih0RQAGHADAFRIRMoghhBAyHUKFCGKIIYIUQtGbEemxBRJKWKZQIF4kgYQXxT00BwslgADC
        C00kRIgOL4BQQQk5YPgQDxUMICkEFWR5kBYVPPDAAA5UoJ1DfkwAgQQQQJBABEUeZEOprEKQJHVT
        CrRa6hMI1SBrBDFAFAMEFCQAQQQEgIEQFQhQUGoECTgBkRsBIEAqATLAyAACpSLAgI3LwrAAA1Oc
        2RsNDDBAA1gR9SHGG94iNIgYYggC57sFBQQAOw==
        '''

        self.master_version = master_version
        self.admin_password = admin_password
        self.fwpw_status = fwpw_status
        self.hashed_key = None
        self.obfuscated_keys = None
        self.obfuscated_string = None
        self.cleared_keys = None
        self.postinstall_script = None
        self.plaintext_keys = None
        self.key_item = ''
        self.keys_loaded = False
        self.key_source = ""
        self.state_button_state = "disabled"
        self.hash_button_state = "disabled"

        self.previous_keys = []
        self.current_key = ''

        self.config_options = {}
        self.injest_config()

        self.remote_username = StringVar()
        self.remote_password = StringVar()
        self.remote_hostname = StringVar()

        self.jamf_username = StringVar()
        self.jamf_password = StringVar()
        self.jamf_hostname = StringVar()

        self.jamf_hostname.set("https://jamf.pro.server:8443")
        self.jamf_username.set("")
        self.jamf_password.set("")

        self.hashed_results = StringVar()
        self.fwpm_package_dest = StringVar()
        self.signing_cert = StringVar()
        self.keyfile_loc = StringVar()
        self.status_string = StringVar()
        self.fwpm_package_dest.set("/")
#         self.status_string.set(u'\U0001F923'.encode('utf-8'))
        self.status_string.set("Ready.")
        self.fwpw_enable = IntVar()
        self.fwpw_enable.set(0)
        self.reboot_enable = IntVar()
        self.reboot_enable.set(0)
        self.include_config = IntVar()
        self.include_config.set(0)

        self.use_slack = IntVar()
        self.use_slack.set(0)
        self.slack_identifier = StringVar()
        self.slack_url = StringVar()
        self.slack_info_url = StringVar()
        self.slack_info_channel = StringVar()
        self.slack_info_bot = StringVar()
        self.slack_error_url = StringVar()
        self.slack_error_channel = StringVar()
        self.slack_error_bot = StringVar()
        self.state_string = StringVar()
        self.state_string.set('Firmware password is ' + self.fwpw_status)
        self.keys_loaded_string = StringVar()
        self.keys_loaded_string.set('No keys in memory')
        self.logger.info(self.state_string.get())
        self.logger.info(self.keys_loaded_string.get())

        if self.config_options:
            if self.config_options['slack']['slack_info_url']:
                self.slack_info_url.set(self.config_options['slack']['slack_info_url'])

            if self.config_options['slack']['slack_info_bot_name']:
                self.slack_info_bot.set(self.config_options['slack']['slack_info_bot_name'])

            if self.config_options['slack']['slack_info_channel']:
                self.slack_info_channel.set(self.config_options['slack']['slack_info_channel'])

            if self.config_options['slack']['slack_error_url']:
                self.slack_error_url.set(self.config_options['slack']['slack_error_url'])

            if self.config_options['slack']['slack_error_bot_name']:
                self.slack_error_bot.set(self.config_options['slack']['slack_error_bot_name'])

            if self.config_options['slack']['slack_error_channel']:
                self.slack_error_channel.set(self.config_options['slack']['slack_error_channel'])

            if self.config_options['slack']['slack_identifier']:
                self.slack_identifier.set(self.config_options['slack']['slack_identifier'])

            if self.config_options['slack']['use_slack']:
                # translate into 0/1 for false/true
                self.use_slack.set(1)
                self.slack_optionator()
            else:
                self.use_slack.set(0)

            if self.config_options['keyfile']['path']:
                self.keyfile_loc.set(self.config_options['keyfile']['path'])

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.root.geometry("604x500")

        self.logo_photoimage = PhotoImage(data=self.logo)
        self.closed_lock_icon_photoimage = PhotoImage(data=self.closed_lock_icon)
        self.open_lock_icon_photoimage = PhotoImage(data=self.open_lock_icon)
        self.key_icon_photoimage = PhotoImage(data=self.key_icon)
        self.balloon_icon_photoimage = PhotoImage(data=self.balloon_icon)
        self.shield_icon_photoimage = PhotoImage(data=self.shield_icon)
        self.double_exclamation_icon_photoimage = PhotoImage(data=self.double_exclamation_icon)

        self.superframe = ttk.Frame(self.root, width=604, height=525)
        self.superframe.grid(column=0, row=0, sticky=(N, W, E, S))

        self.logoframe = ttk.Frame(self.superframe, width=604, height=90)
        self.logoframe.grid(column=0, row=0, sticky=(N, W, E, S))

        self.logoframe.grid_rowconfigure(0, weight=1)
        self.logoframe.grid_rowconfigure(2, weight=1)
        self.logoframe.grid_columnconfigure(0, weight=1)
        self.logoframe.grid_columnconfigure(2, weight=1)

        self.logo_label = ttk.Label(self.logoframe)
        self.logo_label['image'] = self.logo_photoimage
        self.logo_label.grid(column=1, row=1, sticky=(N, S, E, W))

        self.stateframe = ttk.Frame(self.superframe, width=604, height=30)
        self.stateframe.grid(column=0, row=1, sticky=(N, W, E, S))
        self.stateframe.grid_columnconfigure(0, weight=1)
        self.stateframe.grid_rowconfigure(0, weight=1)
        self.stateframe.grid_columnconfigure(2, weight=1)
        self.stateframe.grid_rowconfigure(2, weight=1)

        self.lock_label = ttk.Label(self.stateframe)
        if self.fwpw_status == 'On':
            self.lock_label['image'] = self.closed_lock_icon_photoimage
        else:
            self.lock_label['image'] = self.open_lock_icon_photoimage
        self.lock_label.grid(column=0, row=1, sticky=(E))

        self.state_label = ttk.Label(self.stateframe, textvariable=self.state_string, font=("Helvetica", 24))
        self.state_label.grid(column=1, row=1, columnspan=1, sticky=(W))

        self.keys_label = ttk.Label(self.stateframe)
        self.keys_label['image'] = self.balloon_icon_photoimage
        self.keys_label.grid(column=0, row=2, sticky=(E))

        self.keys_loaded_label = ttk.Label(self.stateframe, textvariable=self.keys_loaded_string, font=("Helvetica", 24))
        self.keys_loaded_label.grid(column=1, row=2, columnspan=1, sticky=(W))

        ttk.Separator(self.stateframe, orient=HORIZONTAL).grid(row=10, columnspan=3, sticky=(E, W), pady=0)

        self.navframe = ttk.Frame(self.superframe, width=604, height=30)
        self.navframe.grid(column=0, row=10, sticky=N)

        self.master_pane()

    def master_pane(self):
        """
        The home pane.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])
        self.logger.info("%s" % inspect.stack()[1][3])

        self.mainframe = ttk.Frame(self.superframe, width=604, height=510)
        self.mainframe.grid(column=0, row=2, sticky=(N, W, E, S))

        self.mainframe.grid_rowconfigure(0, weight=1)
        self.mainframe.grid_rowconfigure(5, weight=1)
        self.mainframe.grid_columnconfigure(0, weight=1)
        self.mainframe.grid_columnconfigure(2, weight=1)

        self.change_state_btn = ttk.Button(self.mainframe, width=20, text="Change State", command=self.change_state)
        self.change_state_btn.grid(column=0, row=80, pady=4, columnspan=3)
        self.change_state_btn.configure(state=self.state_button_state)

        self.info_status_label = ttk.Label(self.mainframe, text='Location of keyfile:')
        self.info_status_label.grid(column=0, row=90, pady=8, columnspan=3)

        ttk.Button(self.mainframe, width=20, text="Retrieve from JSS Script", command=self.jss_pane).grid(column=0, row=100, pady=4, columnspan=3)

        ttk.Button(self.mainframe, width=20, text="Fetch from Remote Volume", command=self.remote_nav_pane).grid(column=0, row=200, pady=4, columnspan=3)
        ttk.Button(self.mainframe, width=20, text="Retrieve from Local Volume", command=self.local_nav_pane).grid(column=0, row=300, pady=4, columnspan=3)
        ttk.Button(self.mainframe, width=20, text="Enter Firmware Password", command=self.direct_entry_pane).grid(column=0, row=320, pady=4, columnspan=3)

        ttk.Separator(self.mainframe, orient=HORIZONTAL).grid(row=400, columnspan=3, sticky=(E, W), pady=8)

        hash_display = ttk.Entry(self.mainframe, width=58, textvariable=self.hashed_results)
        hash_display.grid(column=0, row=450, columnspan=4)

        self.hash_btn = ttk.Button(self.mainframe, width=20, text="Copy hash to clipboard", command=self.copy_hash)
        self.hash_btn.grid(column=0, row=500, pady=4, columnspan=3)
        self.hash_btn.configure(state=self.hash_button_state)

        ttk.Separator(self.mainframe, orient=HORIZONTAL).grid(row=700, columnspan=3, sticky=(E, W), pady=8)

        self.status_label = ttk.Label(self.mainframe, textvariable=self.status_string)
        self.status_label.grid(column=0, row=2100, sticky=W, columnspan=2)

        ttk.Button(self.mainframe, text="Quit", width=6, command=self.root.destroy).grid(column=2, row=2100, sticky=E)

    def jss_pane(self):
        """
        JAMF server interaction pane.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])
        self.mainframe.grid_remove()

        try:
            if self.config_options["keyfile"]["remote_type"] == 'jamf':
                if self.config_options["keyfile"]["server_path"]:
                    self.jamf_hostname.set(self.config_options["keyfile"]["server_path"])

                if self.config_options["keyfile"]["username"]:
                    self.jamf_username.set(self.config_options["keyfile"]["username"])

                if self.config_options["keyfile"]["password"]:
                    self.jamf_password.set(self.config_options["keyfile"]["password"])
        except:
            pass

        self.jss_frame = ttk.Frame(self.superframe, width=604, height=510)
        self.jss_frame.grid(column=0, row=2, sticky=(N, W, E, S))

        self.jss_frame.grid_columnconfigure(0, weight=1)
        self.jss_frame.grid_columnconfigure(1, weight=1)
        self.jss_frame.grid_columnconfigure(2, weight=1)
        self.jss_frame.grid_columnconfigure(3, weight=1)

        # 52?
        beam_a = ttk.Button(self.jss_frame, width=5)
        beam_a.grid(column=0, row=0, sticky=W)
        beam_b = ttk.Button(self.jss_frame, width=20)
        beam_b.grid(column=1, row=0, sticky=W)
        beam_c = ttk.Button(self.jss_frame, width=10)
        beam_c.grid(column=2, row=0, sticky=W)
        beam_d = ttk.Button(self.jss_frame, width=16)
        beam_d.grid(column=3, row=0, sticky=W)
        beam_a.grid_remove()
        beam_b.grid_remove()
        beam_c.grid_remove()
        beam_d.grid_remove()

        ttk.Label(self.jss_frame, text="Download keys from Jamf Pro FWPM script:").grid(column=0, row=100, columnspan=4, sticky=(E, W))
        # ttk.Separator(self.hash_frame, orient=HORIZONTAL).grid(row=120, columnspan=50, sticky=(E, W))

        ttk.Label(self.jss_frame, text="Server:").grid(column=0, row=150, sticky=E)
        hname_entry = ttk.Entry(self.jss_frame, width=30, textvariable=self.jamf_hostname)
        hname_entry.grid(column=1, row=150, sticky=W, columnspan=2)

        ttk.Label(self.jss_frame, text="Username:").grid(column=0, row=200, sticky=E)
        uname_entry = ttk.Entry(self.jss_frame, width=30, textvariable=self.jamf_username)
        uname_entry.grid(column=1, row=200, sticky=W, columnspan=2)

        ttk.Label(self.jss_frame, text="Password:").grid(column=0, row=250, sticky=E)
        pword_entry = ttk.Entry(self.jss_frame, width=30, textvariable=self.jamf_password, show="*")
        pword_entry.grid(column=1, row=250, sticky=W, columnspan=2)

        ttk.Button(self.jss_frame, text="Find Script", width=15, default='active', command=self.search_jss).grid(column=1, row=300, columnspan=2, pady=12)

        ttk.Separator(self.jss_frame, orient=HORIZONTAL).grid(row=1000, columnspan=50, pady=12, sticky=(E, W))

        ttk.Button(self.jss_frame, text="Return to home", command=self.master_pane).grid(column=2, row=1100, sticky=E)
        ttk.Button(self.jss_frame, text="Quit", width=6, command=self.root.destroy).grid(column=3, row=1100, sticky=W)

    def direct_entry_pane(self):
        """
        Directly enter fwpw.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        self.current_key = tkSimpleDialog.askstring("FW Password", "Enter firmware password:", show='*', parent=self.root)

        if self.current_key:
            self.keys_loaded = True
            self.calculate_hash()
            self.status_string.set('Keys loaded successfully.')
            self.keys_label['image'] = self.key_icon_photoimage
            self.keys_loaded_string.set('Keys in memory.')
            self.change_state_btn.configure(state="normal")

        else:
            self.flush_keys()
            self.status_string.set('Blank password entered.')
            self.logger.error('Direct enter blank password.')
            self.change_state_btn.configure(state="disabled")

    def remote_nav_pane(self):
        """
        Connect to server and select keyfile.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])
        self.mainframe.grid_remove()

        try:
            if self.config_options["keyfile"]["remote_type"] == 'smb':
                if self.config_options["keyfile"]["server_path"]:
                    self.remote_hostname.set(self.config_options["keyfile"]["server_path"])

                if self.config_options["keyfile"]["username"]:
                    self.remote_username.set(self.config_options["keyfile"]["username"])

                if self.config_options["keyfile"]["password"]:
                    self.remote_password.set(self.config_options["keyfile"]["password"])
        except:
            pass

        self.remote_nav_frame = ttk.Frame(self.superframe, width=604, height=510)
        self.remote_nav_frame.grid(column=0, row=2, sticky=(N, W, E, S))

        self.remote_nav_frame.grid_columnconfigure(0, weight=1)
        self.remote_nav_frame.grid_columnconfigure(1, weight=1)
        self.remote_nav_frame.grid_columnconfigure(2, weight=1)
        self.remote_nav_frame.grid_columnconfigure(3, weight=1)

        ttk.Label(self.remote_nav_frame, text="Read keyfile from remote server: (ie smb://...)").grid(column=0, row=100, columnspan=4, sticky=(E, W))

        ttk.Label(self.remote_nav_frame, text="Server path:").grid(column=0, row=150, sticky=E)
        hname_entry = ttk.Entry(self.remote_nav_frame, width=30, textvariable=self.remote_hostname)
        hname_entry.grid(column=1, row=150, sticky=W, columnspan=2)

        ttk.Label(self.remote_nav_frame, text="Username:").grid(column=0, row=200, sticky=E)
        uname_entry = ttk.Entry(self.remote_nav_frame, width=30, textvariable=self.remote_username)
        uname_entry.grid(column=1, row=200, sticky=W, columnspan=2)

        ttk.Label(self.remote_nav_frame, text="Password:").grid(column=0, row=250, sticky=E)
        pword_entry = ttk.Entry(self.remote_nav_frame, width=30, textvariable=self.remote_password, show="*")
        pword_entry.grid(column=1, row=250, sticky=W, columnspan=2)

        ttk.Button(self.remote_nav_frame, text="Read keyfile", width=15, default='active', command=self.read_remote).grid(column=1, row=300, columnspan=2, pady=12)

        ttk.Separator(self.remote_nav_frame, orient=HORIZONTAL).grid(row=1000, columnspan=50, pady=12, sticky=(E, W))

        ttk.Button(self.remote_nav_frame, text="Return to home", command=self.master_pane).grid(column=2, row=1100, sticky=E)
        ttk.Button(self.remote_nav_frame, text="Quit", width=6, command=self.root.destroy).grid(column=3, row=1100, sticky=W)

    def local_nav_pane(self):
        """
        Select keyfile from local volume.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        self.key_item = tkFileDialog.askopenfilename(title="Local object", message="Select local object:", parent=self.root)

        if self.key_item:
            self.status_string.set('Object found.')
            self.handle_key_item()
        else:
            self.status_string.set('No object selected.')

    def search_jss(self):
        """
        Search the JAMF server for FWPM Control script, strip out and categorize keyfile.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        try:
            jss_search_url = self.jamf_hostname.get() + '/JSSResource/scripts'
            headers = {'Accept': 'application/json', }
            response = requests.get(url=jss_search_url, headers=headers, auth=requests.auth.HTTPBasicAuth(self.jamf_username.get(), self.jamf_password.get()))

            script_list = response.json()

        except requests.exceptions.HTTPError as this_error:
            self.logger.error("http error %s: %s\n" % (response.status_code, this_error))

            if response.status_code == 400:
                self.logger.error("HTTP code {}: {}".format(response.status_code, "Request error."))
            elif response.status_code == 401:
                self.logger.error("HTTP code {}: {}".format(response.status_code, "Authorization error."))
            elif response.status_code == 403:
                self.logger.error("HTTP code {}: {}".format(response.status_code, "Permissions error."))
            elif response.status_code == 404:
                self.logger.error("HTTP code {}: {}".format(response.status_code, "Resource not found."))


        for item in script_list['scripts']:
            if 'FWPM Control' in item['name']:
                target_id = item['id']

        script_url = self.jamf_hostname.get() + '/JSSResource/scripts/id/' + str(target_id)
        headers = {'Accept': 'application/json', }
        response = requests.get(url=script_url, headers=headers, auth=requests.auth.HTTPBasicAuth(self.jamf_username.get(), self.jamf_password.get()))

        response_json = response.json()

        if response.status_code != 200:
            self.logger.info("%i returned." % response.code)
            return

        working_output = response_json['script']['script_contents'].split('\n')
        self.previous_keys = []

        for line in working_output:
            if "'previous':" in line and '#' not in line:
                try:
                    contents = re.findall(r'\s*\'previous\': \[(.*)\]', line)
                    if contents:
                        in_contents = contents[0].split(', ')
                        in_contents = [i for i in in_contents if i]
                        for item in in_contents:
                            subitem = item.split('"')
                            subitem = [i for i in subitem if i]
                            subitem = [i for i in subitem if i != ',']

                            if subitem:
                                self.previous_keys.append(subitem[0])

                except Exception as exception_message:
                    self.logger.error("%s: Unknown error. [%s]" % (inspect.stack()[0][3], exception_message))

            elif "'new':" in line and '#' not in line:
                try:
                    contents = re.findall(r'\s*\'new\': (.*)', line)
                    if contents:
                        if len(contents) == 1:
                            contents = contents[0]
                        else:
                            quit()
                        subitem = contents.split('"')
                        subitem = [i for i in subitem if i]
                        # self.current_key = subitem[0]
                        self.current_key = subitem[0]
                except Exception as exception_message:
                    self.logger.error("%s: Unknown error. [%s]" % (inspect.stack()[0][3], exception_message))

        try:
            self.calculate_hash()
            self.status_string.set('Keys loaded successfully.')
            self.keys_loaded_string.set('Keys copied to memory.')
#             self.hash_button_state
#             self.change_state_btn.configure(state="normal")
        except Exception as exception_message:
            self.logger.error(exception_message)
            self.flush_keys()
#             self.change_state_btn.configure(state="disabled")

    def local_fetch(self):
        """
        Popup simple local navigation dialog.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        self.key_item = tkFileDialog.askopenfilename(title="Local object", message="Select local object:", parent=self.root)

        if self.key_item:
            self.status_string.set('Object found.')
            self.handle_key_item()
        else:
            self.status_string.set('No object selected.')

    def read_remote(self):
        """
        Handle server connection, keyfile selection and remote volume dismount.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        tmp_directory = "/tmp/sk/mount"
        if not os.path.exists(tmp_directory):
            os.makedirs(tmp_directory)

        try:
            self.logger.info("%s: %s" % (inspect.stack()[0][3], "Mounting"))
            msb.mount_share_at_path_with_credentials(self.remote_hostname.get(), tmp_directory, self.remote_username.get(), self.remote_password.get())

            self.key_item = tkFileDialog.askopenfilename(initialdir=tmp_directory, title="Remote object", message="Select remote object:", parent=self.root)

            self.logger.info("%s: %s" % (inspect.stack()[0][3], self.key_item))

            if self.key_item:
                self.status_string.set('Object found.')
                self.handle_key_item()
            else:
                self.status_string.set('No object selected.')

            self.logger.info("%s: %s" % (inspect.stack()[0][3], "Dismounting"))
            umount_results = subprocess.check_output(["/usr/sbin/diskutil", "unmount", tmp_directory])
            self.logger.info(umount_results)

        except Exception as exception_message:
            self.logger.error(exception_message)

    def calculate_hash(self):
        """
        Builds hash identical to FWPM binary.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])
        try:
            hashed_key = hashlib.new('sha256')
            hashed_key.update(self.current_key)

            for entry in sorted(self.previous_keys):
                hashed_key.update(entry)

            fwpw_managed_string = hashed_key.hexdigest()
            self.hashed_results.set(fwpw_managed_string)

            self.keys_label['image'] = self.key_icon_photoimage

            self.hash_btn.configure(state='normal')
            self.change_state_btn.configure(state='normal')

            self.state_button_state = 'normal'
            self.hash_button_state = 'normal'

        except Exception as exception_message:
            self.logger.error(exception_message)

            self.flush_keys()

    def copy_hash(self):
        """
        Provides single button to copy hash to clipboard.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        os.system("echo '%s' | /usr/bin/pbcopy" % self.hashed_results.get())

    def handle_key_item(self):
        """
        attempts to open and parse selected keyfile

        plain text
        obfuscated

        inside dmg --someday
        inside encrypted dmg --someday
        """

        self.logger.info("%s: activated" % inspect.stack()[0][3])

        self.flush_keys()

        if os.path.exists(self.key_item):
            item_filename = self.key_item.split('/')[-1]
            item_extension = item_filename.split('.')[-1]

            if item_extension == 'plist':
                passwords = []
                try:
                    keyfile_plist = plistlib.readPlist(self.key_item)

                    content_raw = keyfile_plist["data"]
                    content_raw = base64.b64decode(content_raw)
                    content_raw = content_raw.split(",")
                    content_raw = [x for x in content_raw if x]

                    for item in content_raw:
                        label, pword = item.split(':')
                        pword = base64.b64decode(pword)

                        if label == 'new':
                            self.current_key = pword
                        else:
                            self.previous_keys.append(pword)

                except Exception as exception_message:
                    self.logger.error("%s: Unknown error. [%s]" % (inspect.stack()[0][3], exception_message))
                    return

            elif item_extension == 'txt':
                try:
                    with open(self.key_item, "r") as keyfile:
                        passwords = keyfile.read().splitlines()

                    for item in passwords:
                        label, pword = item.split(':')

                        if label == 'new':
                            self.current_key = pword
                        else:
                            self.previous_keys.append(pword)

                except Exception as exception_message:
                    self.logger.error("%s: Unknown error. [%s]" % (inspect.stack()[0][3], exception_message))
                    return

            else:
                self.logger.error("%s: Error parsing keyfile." % (inspect.stack()[0][3]))

            self.calculate_hash()

        else:
            # print('no key item')
            # print(self.key_item)
            pass

    def injest_config(self):
        """
        attempts to consume and format configuration file
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        running_pathname = os.path.abspath(os.path.dirname(sys.argv[0]))
        self.logger.info("%s: Application pathname: %s" % (inspect.stack()[0][3], running_pathname))

        config_name = '/fwpm_config.ini'
        config_path = ''

        if os.path.exists(pwd.getpwuid(os.getuid())[5] + '/Library/Preferences' + config_name):
            config_path = pwd.getpwuid(os.getuid())[5] + '/Library/Preferences' + config_name
        else:
            if ".app/Contents" in running_pathname:
                running_root = '/'.join(running_pathname.split('/')[0:-3])
                self.logger.info("%s: Application root folder: %s" % (inspect.stack()[0][3], running_root))

                if os.path.exists(running_root + config_name):
                    config_path = running_root + config_name
            else:
                if os.path.exists(running_pathname + config_name):
                    config_path = running_pathname + config_name

        if not config_path:
            return

        self.logger.info("Configuration file: %s" % config_path)
        if not os.access(config_path, os.R_OK):
            self.logger.critical("Unable to access config file, check privileges.")
            return

        config = ConfigParser.SafeConfigParser(allow_no_value=True)
        config.read(config_path)

        self.config_options["flags"] = {}
        self.config_options["keyfile"] = {}
        self.config_options["logging"] = {}
        self.config_options["slack"] = {}

        for section in ["flags", "keyfile", "logging", "slack"]:
            for item in config.options(section):
                if item.startswith("use_"):
#                 if "use_" in item:
                    try:
                        self.config_options[section][item] = config.getboolean(section, item)
                    except Exception as exception_message:
                        self.config_options[section][item] = False
                        self.logger.error("%s: Invalid/Blank value: %s:%s. [%s]" % (inspect.stack()[0][3], section, item, exception_message))
                elif "path" in item:
                    self.config_options[section][item] = config.get(section, item)
                else:
                    self.config_options[section][item] = config.get(section, item)

        self.logger.info("Configuration file variables:")
        for key, value in self.config_options.items():
            self.logger.info(key)
            for sub_key, sub_value in value.items():
                self.logger.info("\t%s %r" % (sub_key, sub_value))

    def change_state(self):
        """
        Handles toggling of FWPW
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        current_password = ''
        known_current_password = False

        new_fw_tool_path = '/usr/sbin/firmwarepasswd'
        new_fw_tool_exists = os.path.exists(new_fw_tool_path)

        if not new_fw_tool_exists:
            self.logger.critical("firmwarepasswd tool not found.")

        full_keylist = self.previous_keys
        full_keylist.append(self.current_key)

        if self.fwpw_status == 'On':
            self.status_string.set('Attempting to find current password...')
            new_fw_tool_cmd = [new_fw_tool_path, '-verify']
            self.logger.info(' '.join(new_fw_tool_cmd))

            for index in reversed(xrange(len(full_keylist))):

                try:
                    child = pexpect.spawn('bash', ['-c', '/usr/bin/sudo -k /usr/sbin/firmwarepasswd -verify'])

                    exit_condition = False
                    while not exit_condition:
                        result = child.expect(['Password:', 'password:', 'Correct', 'Incorrect', pexpect.EOF, pexpect.TIMEOUT])

                        if result == 0:
                            child.sendline(self.admin_password)
                        elif result == 1:
                            child.sendline(full_keylist[index])
                        elif result == 2:
                            current_password = full_keylist[index]
                            known_current_password = True
                            self.status_string.set('local password found.')
                            self.logger.info('local password found.')
                            break
                        elif result == 3:
                            # self.logger.info('#3.')
                            break
                        elif result == 4:
                            # self.logger.info('#4.')
                            break
                        elif result == 5:
                            # self.logger.info('#5.')
                            break
                        else:
                            self.logger.error("%s: Unknown error. Exiting." % (inspect.stack()[0][3]))
                            return

                    if known_current_password:

                        child = pexpect.spawn('bash', ['-c', '/usr/bin/sudo -k /usr/sbin/firmwarepasswd -delete'])
                        result = child.expect('Password:')

                        if result == 0:
                            child.sendline(self.admin_password)

                            result = child.expect('password:')
                            if result == 0:
                                child.sendline(current_password)

                                result = child.expect(['NOTE', 'ERROR'])
                                if result == 0:
                                    self.logger.info('Off.')
                                elif result == 1:
                                    self.logger.info('PW incorrect.')
                                else:
                                    self.logger.info('Error turning off.')

                        try:
                            child = pexpect.spawn('bash', ['-c', '/usr/bin/sudo -k /usr/sbin/nvram -d fwpw-hash'])
                            result = child.expect('Password:')

                            if result == 0:
                                child.sendline(self.admin_password)

                                result = child.expect('')
                                if result == 0:
                                    self.logger.info('removed nvram.')
                                elif result == 1:
                                    self.logger.info('nvrmam oops 1')
                                else:
                                    self.logger.info('nvram oops 2')

                            else:
                                pass

                        except Exception as exception_message:
                            self.logger.error("%s: Unknown error. [%s]" % (inspect.stack()[0][3], exception_message))

                        self.lock_label['image'] = self.double_exclamation_icon_photoimage
                        self.state_string.set('FW password removed, reboot!')
                        self.slack_message("_*" + self.local_identifier + "*_ :unlock:\n" + "FWPW and nvram entry removed.", '', 'info')

                        break

                except Exception as exception_message:
                    self.logger.error("%s: Unknown error. [%s]" % (inspect.stack()[0][3], exception_message))

        else:  # self.fwpw_status == 'Off'

            #  ~/Box Sync/working stuff @ box/FWPM/skeleton key 4:48pm root@t-mcdaniel-mac-laptop #170 ]firmwarepasswd -setpasswd
            # Setting Firmware Password
            # Enter password:
            # Enter new password:
            # Re-enter new password:
            # ERROR | setPasswdFromCommandLine | Unable to verify password
            # ERROR | main | Exiting with error: 4

            self.logger.info("Setting FW password")

            self.logger.info("Using %s" % self.current_key)
            if not self.current_key:
                self.logger.error('Blank key.')
                return

            child = pexpect.spawn('bash', ['-c', '/usr/bin/sudo -k /usr/sbin/firmwarepasswd -setpasswd'])
            result = child.expect('Password:')

            if result == 0:
                child.sendline(self.admin_password)

                result = child.expect('password:')
                if result == 0:
                    child.sendline(self.current_key)
                else:
                    pass

                result = child.expect('new password:')
                if result == 0:
                    child.sendline(self.current_key)

                    result = child.expect(['NOTE', 'ERROR'])
                    if result == 0:
                        self.logger.info('On.')
                    elif result == 1:
                        self.logger.info('PW incorrect.')
                    else:
                        self.logger.info('Error turning off.')

            try:

                child = pexpect.spawn('bash', ['-c', '/usr/bin/sudo -k /usr/sbin/nvram fwpw-hash=2:' + self.hashed_results.get()])
                result = child.expect('Password:')

                if result == 0:
                    child.sendline(self.admin_password)

                    result = child.expect('')
                    if result == 0:
                        self.logger.info('added nvram.')
                    elif result == 1:
                        self.logger.info('nvrmam oops 3')
                    else:
                        self.logger.info('nvram oops 4')

                else:
                    pass

            except Exception as exception_message:
                self.logger.error("%s: Unknown error. [%s]" % (inspect.stack()[0][3], exception_message))

            self.status_string.set('Password activated. Reboot!')
            self.state_string.set('FW password activated, reboot!')
            self.lock_label['image'] = self.shield_icon_photoimage
            self.slack_message("_*" + self.local_identifier + "*_ :closed_lock_with_key:\n" + "FWPW and hash updated.", '', 'info')

    def flush_keys(self):
        """
        Erase loaded keys, reset UI.
        """
        # "secure" erase keys
        # update label
        # deactivate button(s)
        # change icon

        self.previous_keys = []
        self.current_key = ''

        self.keys_label['image'] = self.balloon_icon_photoimage
        self.keys_loaded_string.set('No keys in memory')
        self.hashed_results.set('')

        self.state_button_state = 'disabled'
        self.hash_button_state = 'disabled'

        self.hash_btn.configure(state='disabled')
        self.change_state_btn.configure(state='disabled')

    def slack_message(self, message, icon, msg_type):
        """
        Sends slack messages.
        """
        if self.logger:
            self.logger.info("%s: activated" % inspect.stack()[0][3])

        slack_info_channel = False
        slack_error_channel = False

        if self.config_options["slack"]["use_slack"] and self.config_options["slack"]["slack_info_url"]:
            slack_info_channel = True

        if self.config_options["slack"]["use_slack"] and self.config_options["slack"]["slack_error_url"]:
            slack_error_channel = True

        if slack_error_channel and msg_type == 'error':
            slack_url = self.config_options["slack"]["slack_error_url"]
        elif slack_info_channel:
            slack_url = self.config_options["slack"]["slack_info_url"]
        else:
            return

        payload = {'text': message, 'username': 'Skeleton Key ' + self.master_version, 'icon_emoji': ':old_key:'}

        response = requests.post(slack_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})

        self.logger.info('Response: ' + str(response.text))
        self.logger.info('Response code: ' + str(response.status_code))

    def slack_optionator(self):
        """
        Builds the local identifier string per configuration file.


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
                            if port_name in ether_up_list:
                                device_info_raw = subprocess.check_output(["/sbin/ifconfig", port_name]).decode('utf-8')
                                mac_address = re.findall('ether (.*) \n', device_info_raw)
                                ether_address = re.findall('inet (.*) netmask', device_info_raw)

#                                 if len(ether_address) and len(mac_address):
                                if ether_address and mac_address:
                                    processed_device_list.append([device_name, port_name, ether_address[0], mac_address[0]])
                        except Exception as this_exception:
                            self.logger.error("error discovering device info. [%s]" % this_exception)


                    if processed_device_list:
                        if self.logger:
                            self.logger.info("1 or more active IP addresses. Choosing primary.")

                        if self.config_options["slack"]["slack_identifier"].lower() == 'ip':
                            self.local_identifier = processed_device_list[0][2] + " (" + processed_device_list[0][0] + ":" + processed_device_list[0][1] + ")"
                        elif self.config_options["slack"]["slack_identifier"].lower() == 'mac':
                            self.local_identifier = processed_device_list[0][3] + " (" + processed_device_list[0][0] + ":" + processed_device_list[0][1] + ")"
                        elif self.config_options["slack"]["slack_identifier"].lower() == 'hostname':
                            try:
                                self.local_identifier = socket.getfqdn()
                            except Exception as exception_message:
                                if self.logger:
                                    self.logger.error("error discovering hostname. [%s]" % exception_message)
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
                    except Exception as exception_message:
                        if self.logger:
                            self.logger.info("error discovering computername. [%s]" % exception_message)
                        self.local_identifier = serial_number
                elif self.config_options["slack"]["slack_identifier"].lower() == 'serial':
                    self.local_identifier = serial_number
                    if self.logger:
                        self.logger.info("Serial number: %r" % self.local_identifier)
                else:
                    if self.logger:
                        self.logger.info("bad or no identifier flag, defaulting to serial number.")
                    self.local_identifier = serial_number

            except Exception as this_exception:
                self.logger.error("error verifying network. [%s]" % exception_message)
                self.config_options["slack"]["use_slack"] = False
        else:
            self.config_options["slack"]["use_slack"] = False
            if self.logger:
                self.logger.info("No network detected.")

    def verify_network(self):
        """
        Verifies network availability.

        Host: 8.8.8.8 (google-public-dns-a.google.com)
        OpenPort: 53/tcp
        Service: domain (DNS/TCP)
        """

        try:
            _ = requests.get("https://dns.google.com", timeout=3)
            # _ = requests.get("https://8.8.8.8", timeout=3)
            return True
        except requests.ConnectionError as exception_message:
            self.logger.error("%s: Unknown error. [%s]" % (inspect.stack()[0][3], exception_message))
        return False


def login(root, logger):
    """
    aquire admin password
    """
    logger.info("%s: activated" % inspect.stack()[0][3])

    try:
        root.withdraw()

        if platform.system() == 'Darwin':
            tmpl = 'tell application "System Events" to set frontmost of every process whose unix id is {} to true'
            script = tmpl.format(os.getpid())
            _ = subprocess.check_call(['/usr/bin/osascript', '-e', script])

        password = tkSimpleDialog.askstring("Password", "Enter admin password:", show='*', parent=root)

        if not password:
            logger.error("%s: Canceled login." % (inspect.stack()[0][3]))
            return

        cmd_output = []
        try:
            child = pexpect.spawn('bash', ['-c', '/usr/bin/sudo -k /usr/sbin/firmwarepasswd -check'])

            exit_condition = False
            while not exit_condition:
                result = child.expect(['WARNING:', '\n\nPass', 'Password:', 'attempts', pexpect.EOF, pexpect.TIMEOUT])

                cmd_output.append(child.before)
                cmd_output.append(child.after)
                if result == 0:
                    continue
                elif result == 1:
                    child.sendline(password)
                elif result == 2:
                    child.sendline(password)
                elif result == 3:
                    logger.error("%s: Incorrect admin password." % (inspect.stack()[0][3]))
                    sys.exit()
                elif result == 4:
                    exit_condition = True
                elif result == 5:
                    exit_condition = True
                else:
                    logger.error("%s: Unknown error. Exiting." % (inspect.stack()[0][3]))
                    return
        except Exception as exception_message:
            logger.error("%s: Unknown error. [%s]" % (inspect.stack()[0][3], exception_message))

        #
        # begin parsing out useful content
        checked_output = []
        for value in cmd_output:
            if isinstance(value, basestring):
                if "System\r\nAdministrator." in value:
                    pass
                elif "WARNING" in value:
                    pass
                elif "Improper" in value:
                    pass
                elif value == '\r\n':
                    pass
                elif not value:
                    pass
                elif value == "Password:":
                    pass
                else:
                    checked_output.append(value)

        for item in checked_output:
            if 'Enabled' in item:
                if 'Yes' in item:
                    logger.info("Yes. %r" % item)
                    return password, 'On'
                else:
                    logger.info("No. %r" % item)
                    return password, 'Off'
            else:
                sys.exit()

    except ValueError:
        logger.error("%s: Error here." % (inspect.stack()[0][3]))
        return

    sys.exit()


def main():
    """
    Entry into script.
    """
    master_version = "1.0"

    logging.basicConfig(filename='/tmp/skeleton_key_v' + master_version + '.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    logger.info("Running Skeleton Key " + master_version)

    root = Tk()

    try:
        admin_password, fwpw_status = login(root, logger)
    except Exception as exception_message:
        logger.error("%s: Error logging in. [%s]" % (inspect.stack()[0][3], exception_message))
        sys.exit(0)

    root.deiconify()
    SinglePane(root, logger, admin_password, fwpw_status, master_version)

    root.mainloop()


if __name__ == '__main__':
    main()

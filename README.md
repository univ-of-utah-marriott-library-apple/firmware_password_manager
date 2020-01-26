

# Firmware Password Manager 2.5

A Python script to help Macintosh administrators manage the firmware passwords of their computers.

## Contents

* [Download](#download) - get the .dmg
* [Contact](#contact)
* [System Requirements](#system-requirements)
* [Install](#install)
* [Uninstall](#uninstall)
* [Purpose](#purpose)
  * [Why set the Firmware Password?](#why-set-the-firmware-password)
  * [Firmware Password Manager](#firmware-password-manager)
  * [How FWPM keeps track of the current password](#how-fwpm-keeps-track-of-the-current-password)
* [Usage](#usage)
  * [Options](#options)
  * [The configuration file](#the-configuration-file)
    * [Flags](#flags)
    * [Keyfile](#keyfile)
    * [Logging](#logging)
    * [Slack](#slack)
  * [The keyfile](#the-keyfile)
  * [Security](#security)
  * [Slack integration](#slack-integration)
  * [nvram string](#nvram)
  * [firmwarepasswd](#firmwarepasswd)
  * [Common error messages](#common-error-messages)
  * [JAMF Integration](#jamf-integration)
    * [JAMF FWPM installation policy](#jamf-fwpm-installation-script)
    * [JAMF FWPM controller script](#jamf-fwpm-controller-script)
      * [Editing the keylist variables](#editing-the-keylist-variables)
      * [Editing the configuration file variables](#editing-the-configuration-file-variables)
     * [JAMF JSS extention attribute](#jamf-jss-extention-attribute)
   * [Skeleton Key](#skeleton-key)
      * [Using Skeleton Key](#using-skeleton-key)
         * [Current State](#current-state)
         * [Location](#location)
            * [Retrieve from JSS Script](#retrieve-from-jss-script)
            * [Fetch from Remote Volume](#fetch-from-remote-volume)
            * [Retrieve from Local Volume](#retrieve-from-local-volume)
            * [Enter Firmware Password](#enter-firmware-password)
         * [Keyfile Hash](#keyfile-hash)
         * [Status Messages](#status-messages)
      * [Rebuilding the binary](#rebuilding-the-binary)
* [Notes](#notes)
* [Update History](#update-history)

## Download

[Download the latest installer here!](../../releases/)

## Contact

If you have any comments, questions, or other input, either [file an issue](../../issues) or [send us an email](mailto:mlib-its-mac-github@lists.utah.edu). Thanks!

## System Requirements

* Python 3.7+ (which you can download [here](https://www.python.org/download/))
* Pexpect 3.3+ (which you can download [here](https://github.com/pexpect/pexpect))
* Pyinstaller (which you can download [here](https://www.pyinstaller.org/)) *Only needed if you wish to rebuild either binary.*

## Install

Place the script (or binary) in a root-executable location. We use `/usr/local/sbin/`. Make sure it is executable.

## Uninstall

Remove the script/binary/application.

## Purpose

### Why set the Firmware Password?
In a nutshell, the firmware password in Apple computers prevents non-privileged users from booting from a foreign device.

The firmware password is one of three interlocking methods used to secure Apple computers. The other two are: using strong passwords on user accounts and FileVault to apply full disk encryption (FDE). Strong account passwords are always the first line of defense. FDE effectively scrambles the information written a storage device and renders it unreadable by unauthorized persons. Using all three methods can make a computer unusable should it be lost or stolen.

Depending on the age of computer, removing the firmware password can be easy or incredibly difficult, please refer to the [Notes](#notes) section for more information about removing the password.

### Firmware Password Manager
When I began this project there wasn't a solution available for actively managing firmware passwords, other than the "set-it-and-forget-it" method. This approach seems error-prone and difficult to maintain beyond more than a small handful of machines. My solution centers on maintaining a single list of current and formerly used passwords that I call the keyfile. This approach allows the administrator to easily bring any number of machines up to the current password, and identify those whose firmware passwords aren't in the master list and need additional maintenance.

`firmware_password_manager.py` will use your keyfile to set a firmware password on a machine with no existing firmware password, attempt to change the existing firmware password to your new password or remove the current password. The script is best used when it can be installed and left on the machine for future use. This allows the admin to then create an installer package containing the keyfile and a postflight action to run FWPM. Or the admin could create a launchagent to run FWPM at every boot

Version 2 represents a complete rewrite of Firmware Password Manager (FWPM). The previous version, a shell script, always felt brittle to me. The new version is written in Python. I also focused on utilizing `firmwarepasswd`, rather than the outdated `setregproptool`.

### How FWPM keeps track of the current password

When FWPM successfully sets or changes the firmware password it computes a hash based on the contents of the keyfile and stores the results in nvram. When FWPM is run again on a client it will compare the hash of the current keyfile and the hash stored on the machine, if they are different it will signal the need to change the firmware password to a new value.

A hash can be thought of as the finger print of a file. The goal of a hash function is that no two files will share the same hash value. FWPM uses SHA-256 to generate the hash, or the SHA-2 hash function at a length of 256 bits (32 bytes). Rather than simply hashing the password itself, FWPM hashes the entire keyfile for additional security.

![ScreenShot](img/hash_image.png)

## Usage

```
firmware_password_manager [-h -v] [-c /path/to/configfile]
```



### Options

 Flag | Purpose
--------|---------
`-h`, `--help` | Prints help information and quits.
`-v`, `--version` | Prints version information and quits.
`-c CONFIGFILE`, `--configfile CONFIGFILE` | Specifies the location of the required configuration file.

### The configuration file

Here is the default configuration file included with FWPM:

```
[flags]
use_firmwarepassword: yes
management_string_type: hash
custom_string:
use_reboot_on_exit:

[keyfile]
path: /YourVolume/this/location/example_keyfile.txt
use_obfuscation: No
remote_type: smb
server_path: server_path
username: user_name
password: pass_word

[logging]
use_logging: true
log_path: /tmp

[slack]
use_slack: true
slack_identifier: hostname

slack_info_url: https://hooks.slack.com/services/aaa/bbb/ccc
slack_info_channel: #fwpw_manager_info
slack_info_bot_name: FWPM informational message

slack_error_url: https://hooks.slack.com/services/xxx/yyy/zzz
slack_error_channel: #fwpw_manager_errors
slack_error_bot_name: FWPM error message
```

The configuration file is broken up into sections roughly approximating the command line flags used in the previous versions.



#### Flags

Name | Type|Purpose
--------|---------|---------
use_firmwarepassword|Boolean|Turn FW password on or off.
management_string_type|String|Select the type of management string to use: hash or custom_string. Hash will be used if no value is present. custom_string will use the value in the following variable.
custom_string|String|If you elect to use custom_string, enter it here.
use_reboot_on_exit|Boolean|If you want FWPM to force an immediate reboot on success.


#### Keyfile
Name | Type|Purpose
--------|---------|---------
path| String |Path of the keyfile to be used.
use_obfuscation| Boolean |Use keyfile obfuscation.
remote_type| String |The remote server address to be used.
server_path| String |The path of the keyfile on the server.
username| String |User with adequate privileges on the server to access the keyfile.
password| String |Password for the user.

#### Logging
Name | Type|Purpose
--------|---------|---------
use_logging|Boolean|Create a log file for FWPM.
log_path|String|Path of the log file.

#### Slack
Name | Type|Purpose
--------|---------|---------
use_slack|Boolean|Use Slack messaging.
slack_identifier|String|Method of identifying the message sender on Slack.
||
slack_info_url|String|Slack URL for informational messages.
||
slack_error_url|String|Slack URL for error messages. If not defined messages will be directed to the info channel.



### The keyfile

The script works with a text document I call the keyfile. It contains the new password, as well as any previously used passwords. Having previously used passwords available allows the script to update machines that may have been missed during previous runs of the script.

The script requires a specific format for the keyfile. Each line contains the following: a note string, a colon, and a password string. I assume the newest passwords will be at the end of the file, and the script will try those first. **Only the `new` note has a special meaning, others are ignored.**

Here is the keyfile format:

Notes | Purpose
--------|---------
new|the new password to be installed.
note|any other note strings cause the password to be treated as previously used.
#new|a hash mark will cause the password to be treated as a previously used entry.

Here's an example keyfile:
```
previous:mGoBlue
other:brownCow
#new:short3rPasswd
new:goUtes
```
Version 1 made use of the `current` note to designate what was thought to be current password. Version 2 discovers the current password on its own and will ignore this note.

### Security

The keyfile contains, of course, incredibly sensitive information. When the script successfully completes or encounters an error, it attempts to securely delete the keyfile from the disk.

### Slack integration

We make heavy use of Slack in our office. The `use_slack` option directs FWPM to send informational messages to a slack channel. You simply need to add the URL and channel information for your Slack group to the script. Please see Slack's documentation for additional configuration options: https://api.slack.com/incoming-webhooks

This image shows example FWPM messages in Slack:

![ScreenShot](img/slack_example.png)

The `slack_identifier` option allows you to select how machines are identified in Slack messages. This feature request was issue #2. These flags are mutually exclusive.

String|Purpose
-------|-----------
IP|The IP address of the machine is used. Previous default.
MAC|The MAC address of the current device is used.
computername|The computername is used.
hostname|The fully qualified domain name is used.
serial|The machines serial number is used. If an error occurs discovering the previous methods, FWPM will fall back to this method.

### nvram string

To make the most of FWPM, we suggest using the `management_string_type` flag to store the hash of the keyfile used to create the current firmware password. This allows you to use a variety of tools to remotely check the status of the firmware password on a machine. Using this flag the script will create an SHA-2 hash of the new keyfile and store it in non-volitile RAM (nvram) when the password is changed. The hash can then be accessed locally through the terminal or remotely with SSH, ARD or other tool.

The `custom_string` flag allows you to define any string to place in nvram. You could record the date the password was changed last or a cryptic hint to help you remember the password in the future (not recommended).

### firmwarepasswd

Version 2+ of FWPM uses Apple's `firmwarepasswd` tool to make changes to the firmware password. `firmwarepasswd` was shipped beginning with Mac OS X 10.10 "Yosemite". If you need to manage firmware passwords on OS X prior to 10.10, consider using the previous version of Firmware Password Manager.

### Common error messages

message|description
-------|-----------
Keyfile does not exist.| The script was not able to find the keyfile define by the user, check the path again.
No Firmware password tool available.|The script was unable to find the firmwarepasswd tool. Check that it has not been moved.
Asked to delete, no password set.|The user selected the -r/--remove flag to remove the firmware password, but no firmware password is set.
Malformed keyfile key:value format required.|The keyfile is not properly formatted. Follow the instructions above.
Multiple new keys.|multiple passwords are defined as new in the keyfile, you will need to comment or rename the additional new keys.
No `new` key.|No password in the keyfile has the `new` note, you will need to properly identify the password you wish the use.
Asked to delete, current password not accepted.|For this error to appear something very odd and unexpected has happened, contact the author.
Bad response from firmwarepasswd.|This is a catchall error stating that firmwarepasswd encountered an error.
Current FW password not in keyfile.| This is an critical message that the keyfile does not contain the current password.
nvram reported error.|This is a catchall error stating that nvram encountered an error.
An error occured. Failed to modify firmware password.|This means one of the above errors likely occured. Keep reading the log to find the exact error.

## JAMF Integration

FWPM was originally written to work with our unique management system. During the python rewrite, I made an effort to make FWPM independent of any specific administration philosophy and making it easier to integrate into future management solutions. I've included sample scripts for integrating FWPM into JAMF Casper, UNIX and ARD. The source is included in the example scripts folder.

### JAMF FWPM installation policy

You will need a policy to ensure that the FWPM binary is installed on each of your client machines.

### JAMF FWPM controller script

The controller script directs the automated configuration and launch of FWPM. It contains the new and old firmware passwords, the logic to error check and create an obfuscated keyfile and configuration file, and launches FWPM.

#### Editing the keylist variables

```python
KEYFILE = {
    'previous': ["oneOldPassword", "AnotherPasswordWeUsed"],
    'new': "myNewFWPW!"
}
```

#### Editing the configuration file variables

```python
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

        'slack_info_url': 'https://hooks.slack.com/services/aaaa/bbbbb/cccc',
        'slack_error_url': 'https://hooks.slack.com/services/dddd/eeee/ffff',
    }
}
```

Please see the previous discussion of the configuration file for info on these values.

### JAMF JSS extention attribute

We can leverage the nvram string and smart groups in JAMF Casper to automate the distribution of an updated keyfile package and direct clients to change their firmware passwords. We do this by defining an extension attribute (EA) in the JSS. We've included the script we run in the repository for FWPM 2.0.

The EA script runs during recon and pushes the hash up to the JSS. We then define a smart group that contains any machine not sharing the same hash as the current keyfile. This makes it possible to apply a policy directing those machines to download the new keyfile package and run FWPM.

The following image shows the EA page in the JSS:

![ScreenShot](img/jss_ea.png)

This image shows the two possible smart group built using the EA:

![ScreenShot](img/jss_smart_group.png)

Here is how the smart groups are built:

![ScreenShot](img/jss_not_current.png)

## Skeleton Key

Skeleton Key was written to add a GUI to the firmwarepasswd command and Firmware Password Manager and give it mulitple ways to obtain the keylist file. Skeleton Key is designed to be used by technicians with limited experience or access.

![sk_ui](img/sk_ui.png)

### Using Skeleton Key

Upon launching Skeleton Key, you must enter a valid administrator password to proceed.

<img src="img/sk_login.png" alt="sk_login" style="zoom:50%;" />

You may also see the following message, press OK to continue.

<img src="img/sk_os_alert.png" alt="sk_os_alert" style="zoom:50%;" />

This is the main interface for Skeleton Key. It can be broken down into three areas: Current State, Modifiers and Status messages.

<img src="img/sk_help.png" alt="sk_os_alert" style="zoom:50%;" />



#### Current State

The Current State area will tell you if there is a Firmware password in place, and if the keyfile you have given it was read correctly.

<img src="img/no_keys.png" alt="no_keys" style="zoom:50%;" />



<img src="img/yes_keys.png" alt="yes_keys" style="zoom:50%;" />

#### Location

The Location area is where you will specify the location of the keyfile you wish to use. You can copy it directly from the JSS FWPM controller script, from a remote file share, from a local disk or entered directly into the application.

##### Retrieve from JSS Script

This option allows you to specify the JAMF server that contains the FWPM Controller script for your environment. Skelton Key will parse the script and find the keylist automatically.

##### <img src="img/jamf_fetch_trimmed.png" alt="jamf_fetch_trimmed" style="zoom:50%;" />

##### Fetch from Remote Volume

This option allows you to specify a remote SMB or AFS file share where your keylist is located. Enter the complete URL, username and password.

##### <img src="img/remote_fetch_trimmed.png" alt="remote_fetch_trimmed" style="zoom:50%;" />

##### Retrieve from Local Volume

A standard MacOS X Open File dialog will appear allowing you to navigate to your keyfile.

##### Enter Firmware Password

This option allows you to directly enter the current or new firmware password of the machine.

<img src="img/direct_entry_trimmed.png" alt="direct_entry_trimmed" style="zoom:50%;" />

#### Keyfile hash

When a keyfile is read successfully into memory, the hash will appear here. The hash is used in the JAMF Smart Group, to tell which machines are up to date and which need to be updated.

<img src="img/hashed_keys.png" alt="hashed_keys" style="zoom:50%;" />

#### Status Messages

Any informational or error messages will appear in this location.



### Rebuilding the binary

I use pyinstaller to build the binary. As long as you maintain the file structure, you should be able to rebuild the binary with the following command: `pyinstaller --onefile skeleton_key.py`

## Notes

If you have forgotten the firmware password for a machine your available options depend upon the age of the machine.

Only Apple Retail Stores or Apple Authorized Service Providers can unlock the following Mac models when protected by a firmware password:

 	• iMac (Mid 2011 and later)
 	• iMac Pro (2017)
 	• MacBook (Retina, 12-inch, Early 2015 and later)
 	• MacBook Air (Late 2010 and later)
	• MacBook Pro (Early 2011 and later)
	• Mac mini (Mid 2011 and later)
 	• Mac Pro (Late 2013)

If you can't remember your firmware password or passcode, schedule an in-person service appointment with an Apple Store or Apple Authorized Service Provider. Bring your Mac to the appointment, and bring your original receipt or invoice as proof of purchase.

If you have an earlier machine, it's much easier:

1. Shutdown the machine. Remove the battery, if possible.
2. Change the configuration of RAM by removing a module.
3. Restart the machine and zap the PRAM 3 times. (Hold down Option, Command, p and r after you press the power botton, and wait for three restarts)
4. Shut the machine down and remove the battery, if possible.
5. Reinstall the RAM module.
6. Restart and the firmware password should be removed.

Thank you to macmule for <http://macmule.com/2014/05/11/ea-check-efi-password-state/>, which helped me get things working in version 1.

## Update History

Date | Version | Notes
-------|-----------|-------
2020.01.23 | 2.5 | Removed flags, uses configuration file, removed management_tools, ported to python3. Added Skeleton Key and JAMF Controller script.
2019.10.23 | 2.1.5 | Corrected issue reporting no existing firmware password.
2017.10.23 | 2.1.4 | Using rm -P for secure delete, added additional alerting, additional pylint cleanup.
2016.03.16 | 2.1.2 | Cleaned up argparse, removed obsolete flag logic.
2016.03.16 | 2.1.1 | Slack identifier flag, logic clarifications.
2016.03.07 | 2.1.0 | Obfuscation, reboot flag, bug fixes
2015.11.05 | 2.0.0 | Python rewrite, Docs rewritten
2015.02.25 | 1.0.1 | Added use of firmwarepasswd on 10.10
2014.08.20 | 1.0.0 | Initial version.

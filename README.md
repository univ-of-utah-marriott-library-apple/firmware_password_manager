#firmware_password_manager
=========================

Our previous method for managing Macintosh firmware passwords was developed when Open Firmware was the standard. When Apple moved to increase security and change the location used to store the password, our solution no longer worked. This script was written to be as portable, working in our automated `radmind` environment or installed from another management system. It was written to work in 10.9 Mavericks, but should work in previous versions provided the `setregproptool` is available. 10.10 Yosemite uses a new tool and the script will need to be rewritten to support it.

The script works with a text file I call the keyfile. It contains the current password and the new password. This file is also hashed and stored in nvram for future comparison.

Here is the keyfile format:
```
#							    <-- Lines beginning with hashmarks, "comments" are ignored.
# date of change 			    <-- useful for recording dates, previous hashes, etc.
current:currentpasswword 	    <-- the assumed current password.
new:newpassword 			    <-- the new password to be installed.
```

Here's an example keyfile:
```
# 090414
# olderpassword -for reference
current:shortPassword
new:shinyPassword
```



Thank you to macmule for <http://macmule.com/2014/05/11/ea-check-efi-password-state/>, which helped me get things working.

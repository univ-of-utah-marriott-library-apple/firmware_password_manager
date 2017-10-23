from distutils.core import setup

setup(
    name='Firmware Password Manager',
    version='2.1.4',
    url='https://github.com/univ-of-utah-marriott-library-apple/firmware_password_manager',
    author='Todd McDaniel, Marriott Library IT Services',
    author_email='mlib-its-mac-github@lists.utah.edu',
    description=('A Python script to help Macintosh administrators manage the firmware ',
                 'passwords of their computers.'),
    license='MIT',
    scripts=['firmware_password_manager.py', 'obfuscate_keylist.py'],
    classifiers=[
        'Development Status :: 5 - Stable',
        'Environment :: Console',
        'Environment :: MacOS X',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: MacOS :: MacOS X',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7'
    ],
)

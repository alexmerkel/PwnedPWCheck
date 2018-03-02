PwnedPWCheck
============

What is PwnedPWCheck
--------------------

PwnedPWCheck checks your password against an [online database](https://haveibeenpwned.com/Passwords) of leaked passwords. Passwords that included in a leak should not be used as cracking tools are likly to try these first.

Privacy
-------

PwnedPWCheck does NOT send the entered password to a server. Instead, the first 5 characters of the SHA1 hash of the password are sent. The server replies with a list of pwned password hashes that start with these characters. That way, the server does not learn your password, nor the SHA1 hash of your password or even whether the password you entered is pwned or not. [Learn more](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2#cloudflareprivacyandkanonymity)

Requirements
------------

*   [colored](https://pypi.python.org/pypi/colored)

License
-------

MIT

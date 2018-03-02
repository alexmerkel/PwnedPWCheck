#!/usr/bin/env python3
"""PwnedPWCheck - Checks passwords against HIBP's Pwned Passwords list"""
#
# (c) 2018 Alex Merkel
# @alexandermerkel
#
# See LICENSE file
#


# --------------------------------------------------------------------------- #
# IMPORTS
import sys
import getpass
from hashlib import sha1
from urllib import request
import colored
# ########################################################################### #


# --------------------------------------------------------------------------- #
# VERSION
NAME = "PwnedPWCheck"
VERSION = "0.1.0"
# ########################################################################### #


# --------------------------------------------------------------------------- #
# CONSTANTS
API = "https://api.pwnedpasswords.com/range/"
PREFIXLENGTH = 5
BOLD = colored.attr("bold")
RESET = colored.attr("reset")
RED = colored.fg("red")
GREEN = colored.fg("green")
# ########################################################################### #


# --------------------------------------------------------------------------- #
def main(pws):
    """Main function

    Args:
        pws (list): List of passwords to check or empty for interative mode
    """

    if pws:
        for pw in pws:
            try:
                print(checkPW(pw))
            except Exception:
                print(BOLD+RED+"Connection error!"+RESET)
                break
    else:
        while True:
            try:
                pw = getpass.getpass(prompt="Password to check: ")
                print(checkPW(pw))
            except KeyboardInterrupt:
                print(BOLD+"\nGoodbye..."+RESET)
                break
            except Exception:
                print(BOLD+RED+"Connection error!"+RESET)
                break
# ########################################################################### #


# --------------------------------------------------------------------------- #
def checkPW(pw):
    """Check funtion: Generates SHA1, calls API, evalute response
    Args:
        pw (string): Password to check
    Returns:
        Answer string
    """

    #print(RED+pw+RESET)
    pwHash = generateHash(pw)
    hashes = getPwnedHashes(pwHash)
    (result, number) = evalute(pwHash, hashes)
    if result:
        if number == 1:
            return "{}Password pwned, {}one time!{}".format(RED, BOLD, RESET)
        # More than once in HIBP data
        return "{}Password pwned, {}{} times!{}".format(RED, BOLD, number, RESET)
    # Not in HIBP data
    return "{}Password NOT pwned, congrats!{}".format(GREEN, RESET)
# ########################################################################### #


# --------------------------------------------------------------------------- #
def generateHash(text):
    """Generate SHA1 digest of string
    Args:
        pw (string): Text to hash
    Returns:
        SHA1 hex digest as string
    """
    return sha1(text.encode('utf-8')).hexdigest().upper()
# ########################################################################### #


# --------------------------------------------------------------------------- #
def getPwnedHashes(hashedPW):
    """Check funtion: Generates SHA1, calls API, evalute response
    Args:
        hashedPW (string): Hashed PW
    Returns:
        Content of response
    """
    prefix = hashedPW[:PREFIXLENGTH]
    url = API + prefix
    call = request.Request(url, headers={"User-Agent": NAME+'/'+VERSION})
    return request.urlopen(call, timeout=5).read().decode('utf-8').split('\n')
# ########################################################################### #


# --------------------------------------------------------------------------- #
def evalute(hashedPW, hashes):
    """Check funtion: Generates SHA1, calls API, evalute response
    Args:
        hashedPW (string): Hashed PW
        hashes (string): API response
    Returns:
        Tuple of pwned or not (boolean) and number found (0+)
    """
    suffix = hashedPW[PREFIXLENGTH:]
    for line in hashes:
        if line.startswith(suffix):
            number = int(line[len(suffix)+1:].strip())
            return (True, number)
    return (False, 0)
# ########################################################################### #


# --------------------------------------------------------------------------- #
# Default
if __name__ == "__main__":
    main(sys.argv[1:])
# ########################################################################### #

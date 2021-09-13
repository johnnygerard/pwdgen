#!/usr/bin/python3

# MIT License
#
# Copyright (c) 2021 Johnny Gérard
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from string import ascii_letters, digits, punctuation, ascii_lowercase, ascii_uppercase
from secrets import choice, randbelow
import argparse, sys

parser = argparse.ArgumentParser(prog='pwdgen', formatter_class=argparse.RawTextHelpFormatter, description=
    '''Generate offline secure passwords using a CSPRNG (Cryptographically Strong Pseudo Random Number Generator).
Each character is randomly selected from the ASCII character set (excluding C0 control, space and DEL characters).

By default, all characters are used (same as -z/--all).
Options -e/--exclude and -i/--include override other options (surrounding quotes may be required).''', epilog=
    """ 
EXAMPLES (using default length except for the first):

  4-digit PIN:              pwdgen -d 4
  no symbols:               pwdgen -a
  only symbols:             pwdgen -s
  default:                  pwdgen
  no slashes:               pwdgen -e '\/'
  only slashes and letters: pwdgen -Li '\/'""")
parser.add_argument('length', nargs='?', default=16, type=int, help='number of password characters (default: 16)')
parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')

parser.add_argument('-z', '--all',          action='store_true', help='all characters (default)')
parser.add_argument('-l', '--lowercase',    action='store_true', help='latin small letters (a to z)')
parser.add_argument('-u', '--uppercase',    action='store_true', help='latin capital letters (A to Z)')
parser.add_argument('-L', '--letter',       action='store_true', help='same as -lu')
parser.add_argument('-d', '--digit',        action='store_true', help='decimal digits (0 to 9)')
parser.add_argument('-a', '--alphanumeric', action='store_true', help='same as -Ld')
parser.add_argument('-s', '--symbol',       action='store_true', help='punctuation and symbols')

parser.add_argument('-e', '--exclude', default='', metavar='EXCLUDED', help='string of characters to exclude')
parser.add_argument('-i', '--include', default='', metavar='INCLUDED', help='string of characters to include')

namespace = parser.parse_args()

# validate length argument
if namespace.length <= 0:
    sys.exit('pwdgen: error: length must be positive')

# validate --exclude and --include arguments
excluded_set = set(namespace.exclude)
included_set = set(namespace.include)
if excluded_set & included_set:
    sys.exit('pwdgen: error: conflict between --exclude and --include characters')

# define 4-bit mask
LOWERCASE    = 0b1000
UPPERCASE    = 0b0100
DIGIT        = 0b0010
SYMBOL       = 0b0001

LETTER       = LOWERCASE | UPPERCASE
ALPHANUMERIC = LETTER | DIGIT
ALL          = ALPHANUMERIC | SYMBOL


bitmask = 0
if namespace.all:
    bitmask = ALL
else:
    if namespace.lowercase:    bitmask |= LOWERCASE
    if namespace.uppercase:    bitmask |= UPPERCASE
    if namespace.letter:       bitmask |= LETTER
    if namespace.digit:        bitmask |= DIGIT
    if namespace.alphanumeric: bitmask |= ALPHANUMERIC
    if namespace.symbol:       bitmask |= SYMBOL
    # use default flag (--all)
    if bitmask == 0:           bitmask  = ALL


ascii_lowercase = list(set(ascii_lowercase) - excluded_set if bitmask & LOWERCASE else set(ascii_lowercase) & included_set)
ascii_uppercase = list(set(ascii_uppercase) - excluded_set if bitmask & UPPERCASE else set(ascii_uppercase) & included_set)
digits          = list(set(digits)          - excluded_set if bitmask & DIGIT     else set(digits)          & included_set)
punctuation     = list(set(punctuation)     - excluded_set if bitmask & SYMBOL    else set(punctuation)     & included_set)

selected_characters = digits + punctuation + ascii_lowercase + ascii_uppercase
if len(selected_characters) == 0:
    sys.exit('pwdgen: error: character set empty')
password = []

if namespace.length >= 4:
    # make sure we have at least one character for each non-empty category
    for chars in [digits, punctuation, ascii_lowercase, ascii_uppercase]:
        if len(chars) > 0:
            password.insert(randbelow(len(password) + 1), choice(chars))
            namespace.length -= 1

# remaining characters
for i in range(namespace.length):
    password.insert(randbelow(len(password) + 1), choice(selected_characters))


print(''.join(password))


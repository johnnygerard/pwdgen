#!/usr/bin/env python3
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
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from string import *
from secrets import choice, randbelow
import argparse
import sys

PROG_NAME = 'pwdgen'
parser = argparse.ArgumentParser(
    prog=PROG_NAME,
    formatter_class=argparse.RawTextHelpFormatter,
    description='''Generate offline secure passwords using a CSPRNG\
 (Cryptographically Strong Pseudo Random Number Generator).

By default, each character is randomly selected from the ASCII character set\
 (excluding space and control characters).
The user-defined character set is built in two phases:

    1. Form a base character set using one or more flags (--all\
 when no flags are passed).
    These flags combined define a character superset (equal to their set\
 union).

    2. Add or remove specific characters from base set\
 using the options --include or --exclude.
    These two options may require surrounding quotes and default to the empty\
 string.''',
    epilog="""EXAMPLES

  4-digit PIN: %(prog)s -d 4
  no symbols:  %(prog)s -a
  no slashes:  %(prog)s -e '\\/'
  8-bit key:   %(prog)s -b 8
  base64 key:  %(prog)s -ai '+/'""")

parser.add_argument(
    'length', nargs='?', default=16, type=int,
    help='number of password characters (default: %(default)s)')
parser.add_argument(
    '-v', '--version',  action='version', version='%(prog)s 2.2',
    help="show program's version number and exit\n\n")


def add_flag(short_option, long_option, help_string):
    parser.add_argument(f'-{short_option}', f'--{long_option}',
                        action='store_true', help=help_string)


add_flag('l', 'lowercase', 'latin small letters (a-z)')
add_flag('u', 'uppercase', 'latin capital letters (A-Z)')
add_flag('d', 'digit', 'decimal digits (0-9)')
add_flag('s', 'symbol', 'punctuation and symbols')
add_flag('L', 'letter', 'same as --lowercase --uppercase')
add_flag('a', 'alphanumeric', 'same as --letter --digit')
add_flag('A', 'all', 'same as --alphanumeric --symbol (default)')
add_flag('0', 'empty', 'empty character set (use with --include)')
add_flag('b', 'binary', 'bits (0-1)')
add_flag('o', 'octal', 'octal digits (0-7)')
add_flag('x', 'hex-lower', 'lowercase hexadecimal digits (0-9, a-f)')
add_flag('X', 'hex-upper', 'same as --hex-lower converted to uppercase\n\n')

parser.add_argument(
    '-e', '--exclude', default='', metavar='EXCLUDED',
    help='remove EXCLUDED characters from base set')
parser.add_argument(
    '-i', '--include', default='', metavar='INCLUDED',
    help='add INCLUDED characters to base set\n\n')

parser.add_argument('--pure', action='store_true', help='''Disable the minimum\
 of 1 character applied to digits, symbols, lowercase and uppercase.
Only applies to passwords of length >= 4.
As example: '%(prog)s 4' always contains exactly 1 character of each category.
            '%(prog)s 4 --pure' could produce 0000 or $$$$.''')

namespace = parser.parse_args()

# validate length argument
if namespace.length <= 0:
    sys.exit(f'{PROG_NAME}: error: length must be positive')

# define character sets
LOWERCASE = set(ascii_lowercase)
UPPERCASE = set(ascii_uppercase)
LETTER = LOWERCASE | UPPERCASE
DIGIT = set(digits)
ALPHANUMERIC = LETTER | DIGIT
SYMBOL = set(punctuation)
ALL = ALPHANUMERIC | SYMBOL
BINARY = set('01')
OCTAL = set(octdigits)
HEX_LOWER = DIGIT | set('abcdef')
HEX_UPPER = DIGIT | set('ABCDEF')

excluded_set = set(namespace.exclude)
included_set = set(namespace.include)

# sanitize --exclude and --include arguments
for char in (excluded_set | included_set):
    if char not in ALL:
        sys.exit(f'{PROG_NAME}: error: found unauthorized character\
 (U+{ord(char):04X})')

# check --exclude and --include for conflicts
if excluded_set & included_set:
    sys.exit(f'{PROG_NAME}: error: options --exclude and --include conflict\
 (common characters disallowed)')

# phase 1: combine flags to build the base character set
character_set = set()
if namespace.all:
    character_set = ALL
else:
    if namespace.lowercase:
        character_set |= LOWERCASE
    if namespace.uppercase:
        character_set |= UPPERCASE
    if namespace.letter:
        character_set |= LETTER
    if namespace.digit:
        character_set |= DIGIT
    if namespace.alphanumeric:
        character_set |= ALPHANUMERIC
    if namespace.symbol:
        character_set |= SYMBOL
    if namespace.binary:
        character_set |= BINARY
    if namespace.octal:
        character_set |= OCTAL
    if namespace.hex_lower:
        character_set |= HEX_LOWER
    if namespace.hex_upper:
        character_set |= HEX_UPPER
    # default flag (--all) or --empty
    if not character_set and not namespace.empty:
        character_set = ALL

# phase 2: add or remove using --include and --exclude strings
character_set |= included_set
character_set -= excluded_set

character_list = list(character_set)
if not character_list:
    sys.exit(f'{PROG_NAME}: error: character set empty')
password = []

if namespace.length >= 4 and not namespace.pure:
    # classify characters into 4 categories
    DIGITS = []
    PUNCTUATION = []
    ASCII_LOWERCASE = []
    ASCII_UPPERCASE = []
    for char in character_list:
        if char in digits:
            DIGITS.append(char)
        elif char in ascii_lowercase:
            ASCII_LOWERCASE.append(char)
        elif char in ascii_uppercase:
            ASCII_UPPERCASE.append(char)
        else:
            PUNCTUATION.append(char)

    count = sum([bool(DIGITS),
                 bool(PUNCTUATION),
                 bool(ASCII_LOWERCASE),
                 bool(ASCII_UPPERCASE)])

    for i in range(namespace.length - count):
        password.append(choice(character_list))

    # make sure we have at least one character for each non-empty category
    for chars in [DIGITS, PUNCTUATION, ASCII_LOWERCASE, ASCII_UPPERCASE]:
        if chars:
            # insert instead of append to maintain randomness
            password.insert(randbelow(len(password) + 1), choice(chars))
else:
    # remaining characters
    for i in range(namespace.length):
        password.append(choice(character_list))

print(''.join(password))

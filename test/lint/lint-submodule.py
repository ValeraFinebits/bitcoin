#!/usr/bin/env python3
#
# Copyright (c) 2022-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
This script checks for git modules
"""

import subprocess
import sys


def main():
    submodules = subprocess.check_output(['git', 'submodule', 'status', '--recursive'], text=True).splitlines()
    invalid = [entry for entry in submodules if entry[0] in '+U' or entry.split()[1] != 'payjoin']
    if invalid:
        print("These unexpected or modified submodules were found:\n", '\n'.join(invalid))
        sys.exit(1)
    sys.exit(0)

if __name__ == '__main__':
    main()

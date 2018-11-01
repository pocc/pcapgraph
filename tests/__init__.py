#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""Shared vars/functions for test classes."""

import os

from pcapgraph import get_tshark_status


def setup_testenv():
    """Set up PATH and current working directory."""
    get_tshark_status()
    # If testing from ./tests, change to root directory (useful in PyCharm)
    if os.getcwd().endswith('tests'):
        os.chdir('..')


DEFAULT_CLI_ARGS = {
    '--anonymize': False,
    '--bounded-intersection': False,
    '--difference': False,
    '--exclude-empty': False,
    '--help': False,
    '--intersection': False,
    '--inverse-bounded': False,
    '--output': [],
    '--strip-l2': False,
    '--strip-l3': False,
    '--symmetric-difference': False,
    '--union': False,
    '--verbose': False,
    '--version': False,
    '-w': False,
    '<file>': [],
}

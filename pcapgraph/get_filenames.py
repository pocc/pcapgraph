# -*- coding: utf-8 -*-
# Copyright 2018 Ross Jacobs All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Parse CLI options and return a list of filenames."""

import sys
import os

from .generate_example_pcaps import generate_example_pcaps
from . import __version__


def parse_cli_args(args):
    """Parse args with docopt. Return a list of filenames

    Args:
        args (dict): Dict of args that have been passed in via docopt.
    Return:
        (list): List of filepaths
    """
    if args['--version']:
        print(__version__)
        sys.exit()

    if args['--generate-pcaps']:
        print('Generating pcaps...')
        print(args)
        generate_example_pcaps(interface=args['--int'])
        print('Pcaps sucessfully generated!')
        sys.exit()

    filenames = get_filenames_from_directories(args['--dir'])
    filenames.extend(get_filenames(args['<file>']))
    return filenames


def get_filenames_from_directories(directories):
    """Get all the files from all provided directories.

    Args:
        directories (list): List of user-inputted directories.
    Returns:
        (list): Filenames of all packet captures in specified directories.
    """
    pcap_extensions = [
        '.pcapng', '.pcap', '.cap', '.dmp', '.5vw', '.TRC0', '.TRC1', '.enc',
        '.trc', '.fdc', '.syc', '.bfr', '.tr1', '.snoop'
    ]
    system = sys.platform
    cwd = os.getcwd() + '/'
    filenames = []
    for directory in directories:
        # Tilde expansion on unix systems.
        if directory[0] in '~':
            directory = os.path.expanduser(directory)
        dir_string = directory
        # If the provided path is relative.
        if (system == 'win32' and "C:\\" not in directory.upper()) \
                or (system != 'win32' and directory[0] not in '/'):
            dir_string = cwd + directory
        if not os.path.isdir(dir_string):
            print("ERROR: Directory", dir_string, "not found!")
            sys.exit()
        for file in os.listdir(dir_string):
            for pcap_ext in pcap_extensions:
                if file.endswith(pcap_ext):
                    filenames.append(directory + '/' + file)

    return filenames


def get_filenames(files):
    """Return a list of filenames."""
    pcap_extensions = [
        '.pcapng', '.pcap', '.cap', '.dmp', '.5vw', '.TRC0', '.TRC1', '.enc',
        '.trc', '.fdc', '.syc', '.bfr', '.tr1', '.snoop'
    ]
    cwd = os.getcwd() + '/'
    filenames = []
    for filename in files:
        file_string = filename
        if "C:\\" not in filename.upper():
            file_string = cwd + filename
        if not os.path.isfile(file_string):
            print("ERROR: File", file_string, "not found!")
            sys.exit()
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in pcap_extensions:
            print("ERROR:", filename, "is not a valid packet capture!")
            print("Valid packet capture extensions:", pcap_extensions)
            sys.exit()
        filenames.append(filename)

    return filenames

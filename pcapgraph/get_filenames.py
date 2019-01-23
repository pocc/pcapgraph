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
        print('pcapgraph', __version__)
        print('python', sys.version)
        sys.exit()

    if 'generate-pcaps' in args['--output']:
        print('Generating pcaps...')
        print(args)
        generate_example_pcaps(interface=args['--int'])
        print('Pcaps sucessfully generated!')
        sys.exit()

    has_set_operation = args['--symmetric-difference'] or args['--union'] or \
        args['--difference'] or args['--inverse-bounded'] or \
        args['--bounded-intersection'] or args['--intersection']
    pcap_out = 'pcap' in args['--output'] or 'pcapng' in args['--output']
    if pcap_out and not has_set_operation:
        raise SyntaxError("\nERROR: --output pcap/pcapng needs "
                          "a set operation (-bdeiuy).")

    filenames = get_all_file_and_directory_names(args['<file>'])
    num_files = len(set(filenames).union())
    if has_set_operation and num_files < 2:
        raise SyntaxError("\nERROR: Set operations require 2 or more different"
                          " packet captures (" + str(num_files) + " provided)")
    return filenames


def get_all_file_and_directory_names(file_list):
    """

    Args:
        file_list (list): Every sysarg that doesn't have a flag in front of it.
    Returns:
        (list): List of all filenames
    """
    system = sys.platform
    directories = []
    for index, file in enumerate(file_list):
        # If the provided path is relative.
        if system == 'win32' and "C:\\" not in file.upper():
            extended_file = os.getcwd() + file
        else:
            # Tilde expansion on unix systems.
            if file[0] == '~':
                extended_file = os.path.expanduser(file)
            elif file[0] != '/':
                extended_file = os.getcwd() + '/' + file
            else:
                extended_file = file
        if os.path.isdir(extended_file):
            directories.append(extended_file)
            file_list.remove(file)
        elif os.path.isfile(extended_file):
            file_list[index] = extended_file
        else:
            message = 'File ' + extended_file + ' does not exist!'
            raise FileNotFoundError(message)

    filenames = get_filenames_from_directories(directories)
    filenames.extend(get_filenames(file_list))

    return filenames


def get_filenames_from_directories(directories):
    """Get all the packet captures from all provided directories.

    This function is not recursive and searches one deep.

    Args:
        directories (list): List of user-inputted directories.
    Returns:
        (list): Filenames of all packet captures in specified directories.
    """
    pcap_extensions = [
        '.pcapng', '.pcap', '.cap', '.dmp', '.5vw', '.TRC0', '.TRC1', '.enc',
        '.trc', '.fdc', '.syc', '.bfr', '.tr1', '.snoop'
    ]
    filenames = []
    for directory in directories:
        if not os.path.isdir(directory):
            print("ERROR: Directory", directory, "not found!")
            sys.exit()
        for file in os.listdir(directory):
            for pcap_ext in pcap_extensions:
                if file.endswith(pcap_ext):
                    filenames.append(directory + '/' + file)

    return filenames


def get_filenames(files):
    """Return a validated list of filenames.

    Args:
        files (list): List of file params entered by user
    Returns:
        (list): List of files validated to be packet captures.
    """
    pcap_extensions = [
        '.pcapng', '.pcap', '.cap', '.dmp', '.5vw', '.TRC0', '.TRC1', '.enc',
        '.trc', '.fdc', '.syc', '.bfr', '.tr1', '.snoop'
    ]
    filenames = []
    for filename in files:
        if not os.path.isfile(filename):
            print("ERROR: File", filename, "not found!")
            sys.exit()
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in pcap_extensions:
            print("ERROR:", filename, "is not a valid packet capture!")
            print("Valid packet capture extensions:", pcap_extensions)
            sys.exit()
        filenames.append(filename)

    return filenames

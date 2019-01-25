# -*- coding: utf-8 -*-
"""Start Pcapgraph."""
import sys

import docopt

import pcapgraph.pcapgraph_cli as cli
import pcapgraph.wireshark_io as wireshark_io


def check_requirements():
    """Ensure all pcapgraph requiremens are met."""
    if sys.version_info[0] < 3 or sys.version_info[1] < 5:
        raise EnvironmentError("PcapGraph requires Python 3.5+")
    if sys.getfilesystemencoding().lower() in ("ascii", "ansi_x3.4-1968"):
        raise EnvironmentError("PcapGraph requires a UTF-8 locale.")
    wireshark_io.verify_wireshark()


def start():
    """Start pcapgraph

    Per docopt, pcapgraph with no arguments calls pcapgraph -h.
    If a GUI is ever written, len(sys.argv) == 1 should call it.
    """
    check_requirements()
    args = docopt.docopt(cli.get_docstring())
    cli.init_cli(args)

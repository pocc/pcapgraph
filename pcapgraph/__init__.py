# -*- coding: utf-8 -*-
"""version file."""
__version__ = '1.2.0'

import os
import sys
import time
import subprocess as sp
import webbrowser


def get_tshark_status():
    """Errors and quits if tshark is not installed.

    On Windows, tshark may not be recognized by cmd even if Wireshark is
    installed. On Windows, this function will add the Wireshark folder to path
    so `tshark` can be called.

    Changing os.environ will only affect the cmd shell this program is using
    (tested). Not using setx here as that could be potentially destructive.
    """
    try:
        if sys.platform == 'win32':
            os.environ["PATH"] += os.pathsep + os.pathsep.join(
                ["C:\\Program Files\\Wireshark"])
        tshark_cmds = ['tshark', '-v']
        tshark_pipe = sp.Popen(tshark_cmds, stdout=sp.PIPE, stderr=sp.PIPE)
        tshark_pipe.kill()
    except FileNotFoundError as err:
        print(err, "\nERROR: Requirement tshark from Wireshark not found!",
              "\n       Please install Wireshark or add tshark to your PATH.",
              "\n\nOpening Wireshark download page...")
        time.sleep(2)
        webbrowser.open('https://www.wireshark.org/download.html')
        sys.exit()

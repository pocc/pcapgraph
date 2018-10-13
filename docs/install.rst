Installation
============
Install Steps
-------------
1. Install Wireshark
~~~~~~~~~~~~~~~~~~~~
* These package managers have it in their repositories:
  `apt`, `dnf`, `pacman`, `brew`, `choco`, `...`
* You can also download precompiled binaries [here](https://www.wireshark.org/download.html)

2. Install pcapgraph with pip
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    pip install --user pcapgraph

Installation Errors
-------------------
*These are some misconfiguration errors I came across during testing *
*on Ubuntu. If you have trouble installing, please create an issue.*

_tkinter not installed
~~~~~~~~~~~~~~~~~~~~~~
* On ubuntu, you may need to install the `python3.6-tk` package to
  use the tkinter parts of matplotlib.

ImportError: cannot import name 'multiarray'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If you have versions of numpy or matplotlib that were installed with a
non-3.6 version of python, you may need to reinstall both.

    python -m pip uninstall -y numpy matplotlib
    python -m pip install --user numpy matplotlib

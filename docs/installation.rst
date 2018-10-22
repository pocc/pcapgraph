Install
=======

    *Python is not the only language being used for network automation but the
    combination of being an easy to learn language with many code samples and
    utilities has made it a go-to language for network engineers.*

    -- Cisco DevNet

Install Steps
------------------
.. comment filler for horizontal rule.

----

1. Install Wireshark
~~~~~~~~~~~~~~~~~~~~
* These package managers have it in their repositories:
  ``apt``, ``dnf``, ``pacman``, ``brew``, ``choco``, ``...``
* To download and install precompiled binaries, visit
  `Wireshark's website <https://www.wireshark.org/download.html>`_.

2. Install Python3
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
* This project requires python3.5 or later. ``pip`` is bundled
  with python starting with python3.4.
* You can check your version of python with ``python -V`` in a terminal.
* To download and install precompiled binaries, visit
  `python's website <https://www.python.org/downloads/>`_.

.. note:: macOS comes with Python 2.7 by default. If installing python3
          separately, make sure to add ``alias 'python=python3'`` to your
          .bashrc.

3. Install PcapGraph with pip
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: bash

    pip install --user pcapgraph

Install Errors
--------------
.. comment filler for horizontal rule.

----

.. note:: These are some misconfiguration errors I came across during testing
          on Ubuntu. If you have trouble installing, please create an
          `issue <https://github.com/pocc/pcapgraph/issues>`_.

_tkinter not installed
~~~~~~~~~~~~~~~~~~~~~~
On ubuntu, you may need to install the ``python3-tk`` package to use the
tkinter parts of matplotlib.

ImportError: cannot import name 'multiarray'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If you have versions of numpy or matplotlib that were installed on different
minor versions of python, you may need to reinstall both.

.. code-block:: bash

    python -m pip uninstall -y numpy matplotlib
    python -m pip install --user numpy matplotlib

Testing Install
---------------
.. comment filler for horizontal rule.

----

Test whether pcapgraph is working:

.. code-block:: bash

    pcapgraph -V
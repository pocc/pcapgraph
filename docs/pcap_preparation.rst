Pcap Preparation
================

This program will be most useful if packet captures are filtered for
relevant traffic. The smaller the packet captures are, the faster
pcapgraph is at processing them and the easier it will be to draw
conclusions from exported graphs and packet capures.

Filtering for Relevant Traffic
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
tshark is a utility bundeled with Wireshark that can use filter a pcap
with display filters and save to pcap.

.. code-block:: bash

    tshark -r <in.pcap> -Y "<display filter>" -w <out.pcap>

For example, to filter for ICMP traffic going to/from cloudflare's
DNS service, use "icmp && ip.addr==1.1.1.1" in place of "<display filter>".

More information about tshark usage can be found on the `tshark manpage
<https://www.wireshark.org/docs/man-pages/tshark.html>`_.

Modifying Timestamps
~~~~~~~~~~~~~~~~~~~~
Sometimes, packet captures are taken by devices whose system clocks are off.
If you took the packet capture on a unix-like system, you can get the
time offset with ``ntpdate -q time.nist.gov``.

To modify a packet capture to have the correct timestamps, use editcap:

.. code-block:: bash

    editcap -t <offset> <infile> <outfile>

More information about editcap usage can be found on the `editcap manpage
<https://www.wireshark.org/docs/man-pages/editcap.html>`_
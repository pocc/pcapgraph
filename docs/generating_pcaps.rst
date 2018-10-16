Generating Packet Captures
==========================
.. note:: Generating packet captures is optional if you have cloned the
          repository as pcaps can be found in examples/.
          If you do not have packet captures laying around and you have
          downloaded pcapgraph with pip, then this may provide value.

To generate pcaps by letting tshark decide the default interface, enter

``pcapgraph --generate-pcaps``

If tshark decides to use a non-active interface, you can specify the
interface name manually. To find your active interface, enter ifconfig
(unix-like), or ipconfig (Windows) and find which one has an IP address
and non-zero Rx/Tx counts.

``pcapgraph --generate-pcaps --int <interface-name>``

.. warning:: On unix-like systems, wireshark will prompt you during
             installation to allow/disallow unprivileged users to take
             packet captures. If you have disallowed unprivileged users,
             you may need to use ``sudo`` to capture generated traffic.

Generation Explanation
----------------------
pcapgraph/generate_example_pcaps.py is the relevant file.

The script creates 3 packet captures, each lasting 60 seconds and
starting at 0s, 20s, 40s. After 100s, the script will stop. Packet
capture 0s should have 66% in common with pcap 20s and 33% in common
with pcap 40s. Indeed, this is what we see in the graph.

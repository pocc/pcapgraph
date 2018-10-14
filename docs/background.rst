Miscellaneous Background
========================
Set Theory
----------
.. note:: If you want a primer, you may want to check out the
          `set operations <https://en.wikipedia.org/wiki/Set_(mathematics)
          #Basic_operations>`_ wikipedia article.

Basic Set Operations
~~~~~~~~~~~~~~~~~~~~
The terminology used here is based on set theory. For example, given sets

| A = (1, 2, 3)
| B = (2, 3, 4)
| C = (3, 4, 5)

+----------------------+----------------------+---------------------------------------------------+
| Set Operation        | Applied to (A, B, C) | Definition                                        |
+======================+======================+===================================================+
| Union                |  (1, 2, 3, 4, 5)     | All unique elements.                              |
+----------------------+----------------------+---------------------------------------------------+
| Intersection         | \(3\)                | All common elements.                              |
+----------------------+----------------------+---------------------------------------------------+
| Difference           | \(1\)                | All elements in the first set not in latter sets. |
+----------------------+----------------------+---------------------------------------------------+
| Symmetric Difference | (1, 5)               | All elements unique to only one set.              |
+----------------------+----------------------+---------------------------------------------------+

Packet Uniqueness
~~~~~~~~~~~~~~~~~
By definition, a set only has unique elements. The result of any
set operation is also a set. This program uses the entire frame as an
element to determine uniqueness, which ensures fewer duplicates. The FCS
may be stripped by the NIC depending on network drivers, and so may not
necessarily be available for packet identification (I have only seen Juniper
devices take packet captures that contain the FCS).

Generating Packet Captures
--------------------------
.. note:: Generating packet captures is completely optional as pcaps capturing
          the same packets can be found in the examples folder.

Generation on your machine
~~~~~~~~~~~~~~~~~~~~~~~~~~
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
~~~~~~~~~~~~~~~~~~~~~~
pcapgraph/generate_example_pcaps.py is the relevant file.

The script creates 3 packet captures, each lasting 60 seconds and
starting at 0s, 20s, 40s. After 100s, the script will stop. Packet
capture 0s should have 66% in common with pcap 20s and 33% in common
with pcap 40s. Indeed, this is what we see in the graph.

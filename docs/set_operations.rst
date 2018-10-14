Set Operations
==============
All set operations use the raw frame's hex value to determine uniqueness.
This ensures that unless ARP traffic is involved (which has relatively few
fields), unique frames are going to be correctly identified as such.

.. tip:: These set operations are most useful when the packet captures have
         already been filtered for the traffic that is most relevant.
         The smaller the packet captures are, the faster pcapgraph is at
         processing them and the easier it will be to draw conclusions from
         exported graphs and packet capures.

.. image:: ../examples/pcap_graph.png

This graph was created using ``pcapgraph --dir examples``. The three packet
captures shown here serve as the basis for the set operations below.

Union
-----

Given sets A = (1, 2, 3), B = (2, 3, 4), C = (3, 4, 5), A∪B∪C = (1, 2, 3, 4 ,5)


.. image:: ../examples/set_ops/pcap_graph-union.png

Union will include all unique packets, and so will include the first and last
packets of all captures.

Use case
~~~~~~~~
* For a packet capture that contains a broadcast storm, this function
  will find unique packets and packet counts. Knowing which packets are
  causing a broadcast storm may be useful in determining where there is a
  loop in the network. However, turning off the offending device is not
  likely to remove the loop and broadcast traffic is easy to come by.
* For any other situation where you need to find all unique packets.
* This function can be lossy with timestamps as duplicate packets
  are excluded so information can be lost.

Similar Wireshark Tools
~~~~~~~~~~~~~~~~~~~~~~~
mergecap (<file>) [<file>...] -w union.pcap
    Merges multiple pcaps without removing duplicates.

Intersection
------------

Given sets A = (1, 2, 3), B = (2, 3, 4), C = (3, 4, 5), A∩B∩C = (3)

.. image:: ../examples/set_ops/pcap_graph-intersect.png

Find all packets that are shared between all packet captures.

Use Case
~~~~~~~~
* Taking the intersection of multiple packet captures can provide information
  on what traffic has made it through all relevant devices/interfaces.

Difference
----------
Given sets A = (1, 2, 3), B = (2, 3, 4), C = (3, 4, 5), A-B-C = (1).

.. image:: ../examples/set_ops/pcap_graph-difference.png

Find all packets that are unique to the first packet capture.

Use Case
~~~~~~~~
* Taking the difference between two packet captures can help find traffic
  of interest that is present in one packet capture, but not another.

Symmetric Difference
--------------------

.. image:: ../examples/set_ops/pcap_graph-symdiff.png

Summary
~~~~~~~
Given sets A = (1, 2, 3), B = (2, 3, 4), C = (3, 4, 5), A△B△C = (1, 5)

The symmetric difference includes only unique packets from each packet capture.

Use Case
~~~~~~~~
If you have multiple packet captures in which you want to get all unique
packets exported on a per-packet capture basis.

Caveats
~~~~~~~
Symmetric Difference is included for sake of set operation completeness.
It is the equivalent to the set difference applied to all pcaps where each
pcap is at some point the pivot. If the difference contains no packets, it
is discarded.

Technically, this usage of symmetric difference is incorrect because it
produces multiple packet captures with unique packets instead of one
containing all of them.


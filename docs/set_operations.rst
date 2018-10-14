Set Operations
==============
Sample captures
---------------

simul*.pcap packet captures in examples/ were generated with
``pcapgraph --generate-pcaps --interface wlo1``. For more information on
generating packet captures, please refer to Generating Packet Captures.

.. image:: ../examples/pcap_graph.png

Once the packet captures were generated, this graph was created using
``pcapgraph --dir examples``.

Union
-----

Union will only contain unique values, so frame with transaction id 0xedef
from B and C is removed. Note how the packet capture is reordered according
to time.

.. image:: ../examples/set_ops/pcap_graph-union.png

Use case
~~~~~~~~
* For a packet capture that contains a broadcast storm, this function
  will find unique packets.
* For any other situation where you need to find all unique packets.
* This function can be lossy with timestamps because if duplicate packets
  are excluded, information can be lost.

Similar Wireshark Tools
~~~~~~~~~~~~~~~~~~~~~~~
mergecap (<file>) [<file>...] -w union.pcap
    Merges multiple pcaps without removing duplicates.

Intersection
------------

Save pcap intersection. First filename is pivot packet capture.

.. image:: ../examples/set_ops/pcap_graph-intersect.png

Example
~~~~~~~
Assume all traffic is seen at A and parts of A's traffic are seen at
various other points. This works best with the following kind of scenario:
There is an application that is sending traffic from a client to a
server across the internet

    With that scenario in mind and given these sets,
    A = (1,2,3,4,5)
    B = (1,2,3)
    C = (2,3)
    D = (3,4)

    pcap_intersection([A, B, C, D]) produces package captures and percentages:
    intersection.pcap (3)   20%
    diff_A_B (4, 5)         60%
    diff_A_C (1, 4, 5)      40%
    diff_A_D (1, 2, 5)      40%

    Percentages indicate what percentage of BCD's packets are the same as A's.
    Files starting with 'diff' are set differences of all packets to pivot A.

Difference
----------

Examples
~~~~~~~~
Given sets A = (1, 2, 3), B = (2, 3, 4), C = (3, 4, 5), A-B-C = (1).

.. image:: ../examples/set_ops/pcap_graph-difference.png


Symmetric Difference
--------------------

Symmetric Difference is included for sake of set operation completeness.

.. image:: ../examples/set_ops/pcap_graph-symdiff.png

Example
~~~~~~~~
Given sets A = (1, 2, 3), B = (2, 3, 4), C = (3, 4, 5), A△B△C = (1, 5)

    For all pcaps, the symmetric difference produces a pcap that has the
    packets that are unique to only that pcap (unlike above where only one
    set is the result).
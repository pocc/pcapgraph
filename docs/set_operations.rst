Set Operations
==============
Example packet captures
-----------------------

.. Note that tables are start to wrap at 90 characters. Example table:

+--------+-------+-----------+----------+-----------------+-------------------------------+
| Frame# | Time* | Source IP | Dest IP  | Protocol + Type | Data (truncated)              |
+========+=======+===========+==========+=================+===============================+
| 1      | 1.0   | 10.0.0.2  |  8.8.8.8 | ICMP request    | id=0x6303, seq=1/256, ttl=64  |
+--------+-------+-----------+----------+-----------------+-------------------------------+
| 2      | 1.3   | 8.8.8.8   | 10.0.0.2 | ICMP reply      | id=0x6303, seq=1/256, ttl=121 |
+--------+-------+-----------+----------+-----------------+-------------------------------+

Union
-----
Given packet captures 1 & 2,


About
~~~~~
    This method uses tshark to get identifying information on
    pcaps and then mergepcap to save the combined pcap.

Use case
~~~~~~~~
    * For a packet capture that contains a broadcast storm, this function
      will find unique packets.
    * For any other situation where you need to find all unique packets.
    * This function can be lossy with timestamps because excluding
      packets in diff pcaps with diff timestamps, but same content is the
      purpose of this function.

mergecap
~~~~~~~~
Similar wireshark tool: mergecap <file>... -w union.pcap
    Merges multiple pcaps and saves them as a union.pcap (preserves
    timestamps). This method does the same thing without duplicates.\
    mergecap is shipped with wireshark.

Intersect
---------
Save pcap intersection. First filename is pivot packet capture.

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

Symmetric Difference
-------------------------
Symmetric Difference is included for sake of set operation completeness.

Examplen
~~~~~~~~
Given sets A = (1, 2, 3), B = (2, 3, 4), C = (3, 4, 5), A△B△C = (1, 5)

    For all pcaps, the symmetric difference produces a pcap that has the
    packets that are unique to only that pcap (unlike above where only one
    set is the result).
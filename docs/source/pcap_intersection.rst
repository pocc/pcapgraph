Pcap Intersect
==============
Save pcap intersection. First filename is pivot packet capture.

Example
-------
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
Pcap Union
==========
Given sets A = (1, 2, 3), B = (2, 3, 4), A + B = (1, 2, 3, 4).

About
-----
    This method uses tshark to get identifying information on
    pcaps and then mergepcap to save the combined pcap.

Use case
--------
    * For a packet capture that contains a broadcast storm, this function
      will find unique packets.
    * For any other situation where you need to find all unique packets.
    * This function can be lossy with timestamps because excluding
      packets in diff pcaps with diff timestamps, but same content is the
      purpose of this function.

mergecap
--------
Similar wireshark tool: mergecap <file>... -w union.pcap
    Merges multiple pcaps and saves them as a union.pcap (preserves
    timestamps). This method does the same thing without duplicates.\
    mergecap is shipped with wireshark.
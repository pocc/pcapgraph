CLI usage
=========
PcapGraph
---------

Usage:
   | pcapgraph [-abdeisuVwx] [--output <format>...] (--dir <dir>... | <file>...)
   | pcapgraph (-g | --generate-pcaps) [--int <interface>]
   | pcapgraph (-h | --help)
   | pcapgraph (-v | --version)

Options:
   -a, --anonymize
                         Anonymize packet capture file names with fictional
                         place names and devices.
   -b, --bounded-intersection
                         Bounded intersection of packets (see Set Operations).
   -d, --difference
                         First packet capture minus packets in all succeeding
                         packet captures. (see Set Operations > difference).
   --dir <dir>       Specify directories to add pcaps from (not recursive).
                     Can be used multiple times.
   -e, --inverse-bounded  Shortcut for applying `-b` to a group of pcaps and
                          then subtracting the intersection from each.
   -g, --generate-pcaps  Generate 3 example packet captures (see Generation).
   -h, --help            Show this screen.
   -i, --intersection    All packets that are shared by all packet captures
                         (see Set Operations > intersection).
   --interface <interface>
                         Specify the interface to capture on. Requires -g. Open
                         Wireshark to find the active interface with traffic
                         passing if you are not sure which to specify.
   -o, --output <fmt>    Output results as a file with format type.
   -s, --symmetric-difference
                         Packets unique to each packet capture.
                         (see Set Operations > symmetric difference).
   -u, --union           All unique packets across all pcaket captures.
                         (see Set Operations > union).
   -v, --version         Show PcapGraph's version.
   -V, --verbose         Provide more context to what pcapgraph is doing.
   -w                    Open pcaps in Wireshark after creation.
                        (shortcut for --output pcap --output Wireshark)
   -x, --exclude-empty   eXclude pcap files from being saved if they are empty.

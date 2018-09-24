# PcapGraph
*This is a work in progress and is not up to spec.*
## Scenario
You have a bunch of packet captures all in the same directory and 
want to verify that they were taken at the same time. For some 
troubleshooting paths, being able to see the exact same packets on multiple 
interfaces is required. In order to verify this, you could look at the Unix 
Epoch time in each packet, but that number doesn't make intuitive sense and
 is hard to compare to things. 
 
## Solution
Use tshark to parse the unix times and then use matplotlib to graph the 
timelines so you can visually see when these packet captures were taken.

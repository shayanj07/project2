UCLA CS118 Project (Simple Router)
====================================

For more detailed information about the project and starter code, refer to the project description on CCLE.

(For build dependencies, please refer to [`Vagrantfile`](Vagrantfile).)

## Makefile

The provided `Makefile` provides several targets, including to build `router` implementation.  The starter code includes only the framework to receive raw Ethernet frames and to send Ethernet frames to the desired interfaces.  Your job is to implement the routers logic.

Additionally, the `Makefile` a `clean` target, and `tarball` target to create the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz` turn-in at the top of the file.

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Known Limitations

When POX controller is restrated, the simpler router needs to be manually stopped and started again.

## Acknowledgement

This implementation is based on the original code for Stanford CS144 lab3 (https://bitbucket.org/cs144-1617/lab3).

## Team

Name: Constance Yu
UID: 304652651

contribution: IPv4 package handling, Routing table lookup, and arp cache periodic checkup

Name: Shayan Javid
UID: 905179984

contribution: ARP package handling, ICMP protocal handling, IPv4 package handling

## High Level Implementation

Our router calls `handlePacket` to identify the type of the packet first. If it is an IP
packet, we checks if the destination address is our router. If so, this is a ICMP packet.
We can handle the `ping` and `traceroute` commands separately. If the IP destination is not
our router, we lookup our routing table and find the next hop and interface entry. If we do
not know the IP of the next hop, we check our ARP cache and do ARP request and response handling
if necessary. Here, if the needed requirements for forwarding packets are not met, we queue it. 
The logic if ARP handling is followed: if the ARP request is to the router, it generates an ARP
response. If it is an ARP reply, we update ARP cache and forward package.

## Problem

The first and most obvious problem we ran into was misunderstanding the architecture of our router.
TA Tianxiang was really helpful because he went through the structure of project 2 in discussion.
We were having trouble displaying the correct address when we received the ICMP `traceroute` command at first. Instead of displaying each hop, our router would only display the last hop
address incorrectly. We debugged this by revisiting how we update the address in the router and
found and fixed the bug. The longest prefix matching was also another method we did not understand
properly before and thus implemented error code. It did not work and when we tried to transport
files, our router would always go core dump... Then we realized we need to keep track of the
*longest* prefix instead of just the first matching prefix.
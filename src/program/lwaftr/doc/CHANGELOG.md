# Change Log

## [2.3] - 2016-02-17

A bug fix and performance improvement release.

 * Fix case in which TTL of ICMPv4 packets was not always being
   decremented.

 * Fix memory leaks when dropping packets due to 0 TTL, failed binding
   table lookup, or other errors that might cause ICMP error replies.

 * Fix hairpinning of ICMP error messages for non-existent IPv4 hosts.
   Before, these errors always were going out the public IPv4 interface
   instead of being hairpinned if needed.

 * Fix hairpinning of ICMP error messages for incoming IPv4 packets
   whose TTL is 0 or 1. Before, these errors always were going out the
   public IPv4 interface instead of being hairpinned if needed.

 * Fix hairpinning of ICMP error messages for packets with the DF bit
   that would cause fragmentation. Likewise these were always going out
   the public interface.

 * Allow B4s that have access to port 0 on their IPv4 address to be
   pinged from the internet or from a hairpinned B4, and to reply.  This
   enables a B4 with a whole IPv4 address to be pinged.  Having any
   reserved ports on an IPv4 address will prevent any B4 on that IPv4
   from being pinged, as reserved ports make port 0 unavailable.

 * Switch to stream in results from binding table lookups in batches of
   32 using optimized assembly code.  This increases performance
   substantially.

## [2.2] - 2016-02-11

Adds `--ring-buffer-size` argument to `snabb lwaftr run` which can
increase the receive queue size.  This won't solve packet loss when the
lwaftr is incapable of handling incoming throughput, but it might reduce
packet loss due to jitter in the `breathe()` times.  The default size is
512 packets; any power of 2 up to 32K is accepted.

Also, fix `snabb lwaftr run -v -v` (multiple `-v` options).  This will
periodically print packet loss statistics to the console.  This can
measure ingress packet loss as it is taken from the NIC counters.

## [2.1] - 2016-02-10

A bug-fix release to fix VLAN tagging/untagging when offloading this
operation to the 82599 hardware.

## [2.0] - 2016-02-09

A major release; see the documentation at
https://github.com/Igalia/snabb/tree/lwaftr_starfruit/src/program/lwaftr/doc
for more details on how to use all of these features.  Besides
bug-fixes, notable additions include:

 * Support for large binding tables with millions of softwires.  The
   binding table will be compiled to a binary format as needed, and may
   be compiled to a binary file ahead of time.

 * The configuration file syntax and the binding table syntax have
   changed once again.  We apologize for the inconvenience, but it
   really is for the better: now, address-sharing softwires can be
   specified directly using the PSID format.

 * Support for virtualized operation using `virtio-net`.

 * Support for discovery of next-hop L2 addresses on the B4 side via
   neighbor discovery.

 * Support for ingress and egress filters specified in `pflang`, the
   packet filtering language of language of `tcpdump`.

 * Ability to reload the binding table via a `snabb lwaftr control`
   command.

## [1.2] - 2015-12-10

Fix bugs related to VLAN tagging on port-restricted IP addresses.

Fix bugs related to ICMPv6 and hairpinning.

## [1.1] - 2015-11-25

This release has breaking configuration file changes for VLAN tags and
MTU sizes; see details below.

This release fixes VLAN tagging for outgoing ICMP packets. Outgoing ICMP
worked without VLANs, and now also works with them. Incoming ICMP
support looked broken as a side effect of the outgoing ICMP messages
with VLAN tags translated by the lwAftr not being valid. The primary
test suite has been upgraded to be equally comprehensive with and
without vlan support.

This release contains fragmentation support improvements. It fixes a
leak in IPv6 fragmentation reassembly, and enables IPv4 reassembly. For
best performance, networks should be configured to avoid fragmentation
as much as possible.

This release also allows putting a ```debug = true,``` line into
configuration files (ie, the same file where vlan tags are
specified). If this is done, verbose debug information is shown,
including at least one message every time a packet is received. This
mode is purely for troubleshooting, not benchmarking.

*Please note that there are two incompatible changes to the
 configuration file format.*

Firstly, the format for specifying VLAN tags has changed incompatibly.
Instead of doing:

```
v4_vlan_tag=C.htonl(0x81000444),
v6_vlan_tag=C.htonl(0x81000666),
```

the new format is:

```
v4_vlan_tag=0x444,
v6_vlan_tag=0x666,
```

We apologize for the inconvenience.

Secondly, the way to specify MTU sizes has also changed incompatibly.
Before, the `ipv4_mtu` and `ipv6_mtu` implicitly included the size for
the L2 header; now they do not, instead only measuring the packet size
from the start of the IPv4 or IPv6 header, respectively.

## [1.0] - 2015-10-01

### Added

- Static configuration of the provisioned set of subscribers and their mapping
to IPv4 addresses and port ranges from a text file (binding table).
- Static configuration of configurable options from a text file (lwaftr.conf).
- Feature-complete encapsulation and decapsulation of IPv4-in-IPv6.
- ICMPv4 handling: configurable as per RFC7596.
- ICMPv6 handling, as per RFC 2473.
- Feature-complete tunneling and traffic class mapping, with first-class support
for IPv4 packets containing UDP, TCP, and ICMP, as per RFCs 6333, 2473 and 2983.
- Feature-complete configurable error handling via ICMP messages, for example 
"destination unreachable", "host unreachable", "source address failed 
ingress/egress filter", and so on as specified.
- Association of multiple IPv6 addresses for an lwAFTR, as per draft-farrer-
softwire-br-multiendpoints.
- Full fragmentation handling, as per RFCs 6333 and 2473.
- Configurable (on/off) hairpinning support for B4-to-B4 packets.
- A static mechanism for rate-limiting ICMPv6 error messages.
- 4 million packets per second (4 MPPS) in the following testing configuration:
   - Two dedicated 10G NICs: one internet-facing and one subscriber facing (2 MPPS per NIC)
   - 550-byte packets on average.
   - A small binding table.
   - "Download"-like traffic that stresses encapsulation speed
   - Unfragmented packets
   - Unvirtualized lwAFTR process
   - A single configured IPv6 lwAFTR address.
- Source:
   - apps/lwaftr: Implementation of the lwAFTR.
- Programs:
   - src/program/snabb_lwaftr/bench: Used to get an idea of the raw speed of the
lwaftr without interaction with NICs
   - src/program/snabb_lwaftr/check: Used in the lwAFTR test suite. 
   - src/program/snabb_lwaftr/run: Runs the lwAFTR.
   - src/program/snabb_lwaftr/transient: Transmits packets from a PCAP-FILE to 
the corresponding PCI network adaptors. Starts at zero bits per second, ramping 
up to BITRATE bits per second in increments of STEP bits per second.
- Tests:
   - src/program/tests:
      - end-to-end/end-to-end.sh: Feature tests.
      - data: Different data samples, binding tables and lwAFTR configurations.
      - benchdata: Contains IPv4 and IPv6 pcap files of different sizes.

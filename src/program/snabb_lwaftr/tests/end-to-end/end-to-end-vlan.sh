#!/bin/bash

SNABB_LWAFTR=../../../../snabb-lwaftr
TEST_CONF=../data
TEST_DATA=../data/vlan
TEST_OUT=/tmp
EMPTY=${TEST_CONF}/empty.pcap

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

function quit_with_msg {
   echo $1; exit 1
}

function scmp {
    if ! cmp $1 $2 ; then
        ls -l $1
        ls -l $2
        quit_with_msg "$3"
    fi
}

function snabb_run_and_cmp {
   rm -f ${TEST_OUT}/endoutv4.pcap ${TEST_OUT}/endoutv6.pcap
   if [ -z $5 ]; then
      echo "not enough arguments to snabb_run_and_cmp"
      exit 1
   fi

   ${SNABB_LWAFTR} check \
      $1 $2 $3 ${TEST_OUT}/endoutv4.pcap ${TEST_OUT}/endoutv6.pcap || quit_with_msg \
        "Failure: ${SNABB_LWAFTR} check \
         $1 $2 $3 \
         ${TEST_OUT}/endoutv4.pcap ${TEST_OUT}/endoutv6.pcap"
   scmp $4 ${TEST_OUT}/endoutv4.pcap \
    "Failure: ${SNABB_LWAFTR} check $1 $2 $3 $4 $5"
   scmp $5 ${TEST_OUT}/endoutv6.pcap \
    "Failure: ${SNABB_LWAFTR} check $1 $2 $3 $4 $5"
   echo "Test passed"
}

echo "Testing: from-internet IPv4 packet found in the binding table."
snabb_run_and_cmp ${TEST_CONF}/icmp_on_fail_vlan.conf \
   ${TEST_DATA}/tcp-frominet-bound.pcap ${EMPTY} \
   ${EMPTY} ${TEST_DATA}/tcp-afteraftr-ipv6.pcap

echo "Testing: traffic class mapping"
snabb_run_and_cmp ${TEST_CONF}/icmp_on_fail_vlan.conf \
   ${TEST_DATA}/tcp-frominet-trafficclass.pcap ${EMPTY} \
   ${EMPTY} ${TEST_DATA}/tcp-afteraftr-ipv6-trafficclass.pcap

echo "Testing: from-internet IPv4 packet found in the binding table, original TTL=1."
snabb_run_and_cmp ${TEST_CONF}/icmp_on_fail_vlan.conf \
   ${TEST_DATA}/tcp-frominet-bound-ttl1.pcap ${EMPTY}\
   ${TEST_DATA}/icmpv4-time-expired.pcap ${EMPTY}

echo "Testing: from-internet IPv4 fragmented packets found in the binding table"
snabb_run_and_cmp ${TEST_CONF}/icmp_on_fail_vlan.conf \
	${TEST_DATA}/tcp-ipv4-3frags-bound.pcap ${EMPTY} \
	${EMPTY} ${TEST_DATA}/tcp-afteraftr-ipv6-reassembled.pcap

echo "Testing: from-B4 IPv4 fragmentation (2)"
snabb_run_and_cmp ${TEST_CONF}/small_ipv4_mtu_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/tcp-ipv6-fromb4-toinet-1046.pcap \
   ${TEST_DATA}/tcp-ipv4-toinet-2fragments.pcap ${EMPTY}

echo "Testing: from-B4 IPv4 fragmentation (3)"
snabb_run_and_cmp ${TEST_CONF}/small_ipv4_mtu_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/tcp-ipv6-fromb4-toinet-1500.pcap \
   ${TEST_DATA}/tcp-ipv4-toinet-3fragments.pcap ${EMPTY}

echo "Testing: from-internet IPv4 packet found in the binding table, needs IPv6 fragmentation (2)."
snabb_run_and_cmp ${TEST_CONF}/small_ipv6_mtu_no_icmp_vlan.conf \
   ${TEST_DATA}/tcp-frominet-bound1494.pcap ${EMPTY} \
   ${EMPTY} ${TEST_DATA}/tcp-afteraftr-ipv6-2frags.pcap

echo "Testing: from-internet IPv4 packet found in the binding table, needs IPv6 fragmentation (3)."
snabb_run_and_cmp ${TEST_CONF}/small_ipv6_mtu_no_icmp_vlan.conf \
   ${TEST_DATA}/tcp-frominet-bound-2734.pcap ${EMPTY} \
   ${EMPTY} ${TEST_DATA}/tcp-afteraftr-ipv6-3frags.pcap

echo "Testing: IPv6 reassembly (followed by decapsulation)."
snabb_run_and_cmp ${TEST_CONF}/small_ipv6_mtu_no_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/tcp-ipv6-2frags-bound.pcap \
   ${TEST_DATA}/tcp-ipv4-2ipv6frags-reassembled.pcap ${EMPTY}

echo "Testing: from-internet IPv4 packet found in the binding table, needs IPv6 fragmentation, DF set, ICMP-3,4."
snabb_run_and_cmp ${TEST_CONF}/small_ipv6_mtu_no_icmp_vlan.conf \
   ${TEST_DATA}/tcp-frominet-bound1494-DF.pcap  ${EMPTY} \
   ${TEST_DATA}/icmpv4-fromlwaftr-replyto-tcp-frominet-bound1494-DF.pcap ${EMPTY}

echo "Testing: from-internet IPv4 packet NOT found in the binding table, no ICMP."
snabb_run_and_cmp ${TEST_CONF}/no_icmp_vlan.conf \
   ${TEST_DATA}/tcp-frominet-unbound.pcap ${EMPTY} \
   ${EMPTY} ${EMPTY}

echo "Testing: from-internet IPv4 packet NOT found in the binding table (matches IPv4, but not port), no ICMP."
snabb_run_and_cmp ${TEST_CONF}/no_icmp_vlan.conf \
   ${TEST_DATA}/tcp-frominet-ip-bound-port-unbound.pcap ${EMPTY} \
   ${EMPTY} ${EMPTY}

echo "Testing: from-internet IPv4 packet NOT found in the binding table (ICMP-on-fail)."
snabb_run_and_cmp ${TEST_CONF}/icmp_on_fail_vlan.conf \
   ${TEST_DATA}/tcp-frominet-unbound.pcap ${EMPTY} \
   ${TEST_DATA}/icmpv4-dst-host-unreachable.pcap ${EMPTY}

echo "Testing: from-internet IPv4 packet NOT found in the binding table (matches IPv4, but not port) (ICMP-on-fail)."
snabb_run_and_cmp ${TEST_CONF}/icmp_on_fail_vlan.conf \
   ${TEST_DATA}/tcp-frominet-ip-bound-port-unbound.pcap ${EMPTY} \
   ${TEST_DATA}/icmpv4-dst-host-unreachable-ip-bound-port-unbound.pcap ${EMPTY}

echo "Testing: from-to-b4 IPv6 packet NOT found in the binding table, no ICMP."
snabb_run_and_cmp ${TEST_CONF}/no_icmp_vlan.conf \
   ${TEST_DATA}/tcp-afteraftr-ipv6.pcap ${EMPTY} \
   ${EMPTY} ${EMPTY}

echo "Testing: from-b4 to-internet IPv6 packet found in the binding table."
snabb_run_and_cmp ${TEST_CONF}/no_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/tcp-fromb4-ipv6.pcap \
   ${TEST_DATA}/decap-ipv4.pcap ${EMPTY}

echo "Testing: from-b4 to-internet IPv6 packet NOT found in the binding table, no ICMP"
snabb_run_and_cmp ${TEST_CONF}/no_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/tcp-fromb4-ipv6-unbound.pcap \
   ${EMPTY} ${EMPTY}

echo "Testing: from-b4 to-internet IPv6 packet NOT found in the binding table (matches IPv4, but not port), no ICMP"
snabb_run_and_cmp ${TEST_CONF}/no_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/tcp-fromb4-ipv6-bound-port-unbound.pcap \
   ${EMPTY} ${EMPTY}

echo "Testing: from-b4 to-internet IPv6 packet NOT found in the binding table (ICMP-on-fail)"
snabb_run_and_cmp ${TEST_CONF}/icmp_on_fail_vlan.conf \
   ${EMPTY} ${TEST_DATA}/tcp-fromb4-ipv6-unbound.pcap \
   ${EMPTY} ${TEST_DATA}/icmpv6-nogress.pcap

echo "Testing: from-b4 to-internet IPv6 packet NOT found in the binding table (matches IPv4, but not port) (ICMP-on-fail)"
snabb_run_and_cmp ${TEST_CONF}/icmp_on_fail_vlan.conf \
   ${EMPTY} ${TEST_DATA}/tcp-fromb4-ipv6-bound-port-unbound.pcap \
   ${EMPTY} ${TEST_DATA}/icmpv6-nogress-ip-bound-port-unbound.pcap

echo "Testing: from-to-b4 IPv6 packet, no hairpinning"
# The idea is that with hairpinning off, the packet goes out the inet interface
# and something else routes it back for re-encapsulation. It's not clear why
# this would be desired behaviour, but it's my reading of the RFC.
snabb_run_and_cmp ${TEST_CONF}/no_hairpin_vlan.conf \
   ${EMPTY} ${TEST_DATA}/tcp-fromb4-tob4-ipv6.pcap \
   ${TEST_DATA}/decap-ipv4-nohair.pcap ${EMPTY}

echo "Testing: from-to-b4 IPv6 packet, with hairpinning"
snabb_run_and_cmp ${TEST_CONF}/no_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/tcp-fromb4-tob4-ipv6.pcap \
   ${EMPTY} ${TEST_DATA}/recap-ipv6.pcap

echo "Testing: from-b4 IPv6 packet, with hairpinning, to B4 with custom lwAFTR address"
snabb_run_and_cmp ${TEST_CONF}/no_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/tcp-fromb4-tob4-customBRIP-ipv6.pcap \
   ${EMPTY} ${TEST_DATA}/recap-tocustom-BRIP-ipv6.pcap

echo "Testing: from-b4 IPv6 packet, with hairpinning, from B4 with custom lwAFTR address"
snabb_run_and_cmp ${TEST_CONF}/no_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/tcp-fromb4-customBRIP-tob4-ipv6.pcap \
   ${EMPTY} ${TEST_DATA}/recap-fromcustom-BRIP-ipv6.pcap

echo "Testing: from-b4 IPv6 packet, with hairpinning, different non-default lwAFTR addresses"
snabb_run_and_cmp ${TEST_CONF}/no_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/tcp-fromb4-customBRIP1-tob4-customBRIP2-ipv6.pcap \
   ${EMPTY} ${TEST_DATA}/recap-customBR-IPs-ipv6.pcap

# Test UDP packets
echo "Testing: from-internet bound IPv4 UDP packet"
snabb_run_and_cmp ${TEST_CONF}/icmp_on_fail_vlan.conf \
   ${TEST_DATA}/udp-frominet-bound.pcap ${EMPTY} \
   ${EMPTY} ${TEST_DATA}/udp-afteraftr-ipv6.pcap

echo "Testing: unfragmented IPv4 UDP -> outgoing IPv6 UDP fragments"
snabb_run_and_cmp ${TEST_CONF}/small_ipv6_mtu_no_icmp_vlan.conf \
   ${TEST_DATA}/udp-frominet-bound.pcap ${EMPTY} \
   ${EMPTY} ${TEST_DATA}/udp-afteraftr-ipv6-2frags.pcap

echo "Testing: IPv6 incoming UDP fragments -> unfragmented IPv4"
snabb_run_and_cmp ${TEST_CONF}/icmp_on_fail_vlan.conf \
   ${EMPTY} ${TEST_DATA}/udp-fromb4-2frags-bound.pcap \
   ${TEST_DATA}/udp-afteraftr-reassembled-ipv4.pcap ${EMPTY}

echo "Testing: IPv6 incoming UDP fragments -> outgoing IPv4 UDP fragments"
snabb_run_and_cmp ${TEST_CONF}/small_ipv4_mtu_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/udp-fromb4-2frags-bound.pcap \
   ${TEST_DATA}/udp-afteraftr-ipv4-3frags.pcap ${EMPTY}

echo "Testing: IPv4 incoming UDP fragments -> outgoing IPv6 UDP fragments"
snabb_run_and_cmp ${TEST_CONF}/small_ipv6_mtu_no_icmp_vlan.conf \
   ${TEST_DATA}/udp-frominet-3frag-bound.pcap ${EMPTY} \
   ${EMPTY} ${TEST_DATA}/udp-afteraftr-reassembled-ipv6-2frags.pcap

# Test ICMP inputs (with and without drop policy)
echo "Testing: incoming ICMPv4 echo request, matches binding table"
snabb_run_and_cmp ${TEST_CONF}/tunnel_icmp_vlan.conf \
   ${TEST_DATA}/incoming-icmpv4-echo-request.pcap ${EMPTY} \
   ${EMPTY} ${TEST_DATA}/ipv6-tunneled-incoming-icmpv4-echo-request.pcap

echo "Testing: incoming ICMPv4 echo request, matches binding table"
snabb_run_and_cmp ${TEST_CONF}/tunnel_icmp_vlan.conf \
   ${TEST_DATA}/incoming-icmpv4-echo-request-invalid-icmp-checksum.pcap ${EMPTY} \
   ${EMPTY} ${EMPTY}

echo "Testing: incoming ICMPv4 echo request, matches binding table, dropping ICMP"
snabb_run_and_cmp ${TEST_CONF}/no_icmp_vlan.conf \
   ${TEST_DATA}/incoming-icmpv4-echo-request.pcap ${EMPTY} \
   ${EMPTY} ${EMPTY}

echo "Testing: incoming ICMPv4 echo request, doesn't match binding table"
snabb_run_and_cmp ${TEST_CONF}/tunnel_icmp_vlan.conf \
   ${TEST_DATA}/incoming-icmpv4-echo-request-unbound.pcap ${EMPTY} \
   ${EMPTY} ${EMPTY}

echo "Testing: incoming ICMPv4 echo reply, matches binding table"
snabb_run_and_cmp ${TEST_CONF}/tunnel_icmp_vlan.conf \
   ${TEST_DATA}/incoming-icmpv4-echo-reply.pcap ${EMPTY} \
   ${EMPTY} ${TEST_DATA}/ipv6-tunneled-incoming-icmpv4-echo-reply.pcap

echo "Testing: incoming ICMPv4 3,4 'too big' notification, matches binding table"
snabb_run_and_cmp ${TEST_CONF}/tunnel_icmp_vlan.conf \
   ${TEST_DATA}/incoming-icmpv4-34toobig.pcap ${EMPTY} \
   ${EMPTY} ${TEST_DATA}/ipv6-tunneled-incoming-icmpv4-34toobig.pcap

echo "Testing: incoming ICMPv6 1,3 destination/address unreachable, OPE from internet"
snabb_run_and_cmp ${TEST_CONF}/tunnel_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/incoming-icmpv6-13dstaddressunreach-inet-OPE.pcap \
   ${TEST_DATA}/response-ipv4-icmp31-inet.pcap ${EMPTY}

echo "Testing: incoming ICMPv6 2,0 'too big' notification, OPE from internet"
snabb_run_and_cmp ${TEST_CONF}/tunnel_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/incoming-icmpv6-20pkttoobig-inet-OPE.pcap \
   ${TEST_DATA}/response-ipv4-icmp34-inet.pcap ${EMPTY}

echo "Testing: incoming ICMPv6 3,0 hop limit exceeded, OPE from internet"
snabb_run_and_cmp ${TEST_CONF}/tunnel_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/incoming-icmpv6-30hoplevelexceeded-inet-OPE.pcap \
   ${TEST_DATA}/response-ipv4-icmp31-inet.pcap ${EMPTY}

echo "Testing: incoming ICMPv6 3,1 frag reasembly time exceeded, OPE from internet"
snabb_run_and_cmp ${TEST_CONF}/tunnel_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/incoming-icmpv6-31fragreassemblytimeexceeded-inet-OPE.pcap \
   ${EMPTY} ${EMPTY}

echo "Testing: incoming ICMPv6 4,3 parameter problem, OPE from internet"
snabb_run_and_cmp ${TEST_CONF}/tunnel_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/incoming-icmpv6-43paramprob-inet-OPE.pcap \
   ${TEST_DATA}/response-ipv4-icmp31-inet.pcap ${EMPTY}

echo "Testing: incoming ICMPv6 3,0 hop limit exceeded, OPE hairpinned"
snabb_run_and_cmp ${TEST_CONF}/tunnel_icmp_vlan.conf \
   ${EMPTY} ${TEST_DATA}/incoming-icmpv6-30hoplevelexceeded-hairpinned-OPE.pcap \
   ${EMPTY} ${TEST_DATA}/response-ipv6-tunneled-icmpv4_31-tob4.pcap

echo "All end-to-end lwAFTR tests passed."

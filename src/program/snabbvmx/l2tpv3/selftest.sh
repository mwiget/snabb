#!/usr/bin/env bash

echo "selftest: snabbvmx l2tpv3"

# do tests first that don't require PCI

# lwaftr tap test
NETNS=l2tpv3test

function cleanup {
   set +e
   trap - EXIT SIGINT SIGTERM
   echo ""
   echo "cleaning up"
   sudo ip netns delete $NETNS
}

set -e   # exit immediately if a command terminates with non-zero 
trap cleanup EXIT SIGINT SIGTERM

p="program/snabbvmx/l2tpv3/"
#sudo ./snabb snabbvmx l2tpv3 --read $p/single.pcap --write /tmp/test-ipv6-1-out.pcap --conf $p/test-1.cfg -D 1

# test-ipv4.pcap is a single IPv4 packet that must be passed thru unchanged
sudo ./snabb snabbvmx l2tpv3 --read $p/test-ipv4.pcap --write /tmp/test-ipv4-out.pcap --conf $p/test-1.cfg -D 1
#cant just compare the files in binary, because the timestamps differ.
# use the text version without timestamps to compare:
# tcpdump -n -r test-ipv4.pcap -e -x -t

sudo ./snabb snabbvmx l2tpv3 --read $p/test-ipv6-1.pcap --write /tmp/test-ipv6-1-out.pcap --conf $p/test-1.cfg -D 1
exit

sudo ip netns add $NETNS || exit $TEST_SKIPPED
sudo ip netns exec $NETNS ip tuntap add tapm mode tap
sudo ip netns exec $NETNS ip tuntap add tap0 mode tap
sudo ip netns exec $NETNS ip tuntap add tap1 mode tap
sudo ip netns exec $NETNS ip link set up dev tap0 promisc on
sudo ip netns exec $NETNS ip link set up dev tap1 promisc on
sudo ip netns exec $NETNS ip link add name brtap type bridge
sudo ip netns exec $NETNS ip link set up brtap promisc on
sudo ip netns exec $NETNS ip link set dev tapm master brtap
sudo ip netns exec $NETNS ip link set dev tap0 master brtap
sudo ip netns exec $NETNS ip link set dev tap1 master brtap
srcmac=$(sudo ip netns exec $NETNS ifconfig tap1|grep HWaddr|awk {'print $5'})
dstmac="ff:ff:ff:ff:ff:ff"
sudo ip netns exec $NETNS ./snabb packetblaster lwaftr --src_mac $srcmac --dst_mac $dstmac --tap tap1 -D 5 &
sudo ip netns exec $NETNS tcpdump -n -i tap1 -e -s 1500 -c 3 &
echo "DONE0"
sudo ip netns exec $NETNS ./snabb snabbvmx l2tpv3 --tap tap0 -D 1 -V
echo "DONE1"
sudo ip netns exec $NETNS ifconfig brtap
echo "DONE2"
sudo ip netns exec $NETNS ifconfig tap0
echo "DONE3"
sudo ip netns exec $NETNS ifconfig tap1
echo "DONE4"

echo ""
echo "Testing with configuration file"
echo ""
sudo ip netns exec $NETNS ./snabb snabbvmx l2tpv3 --tap tap0 --conf program/snabbvmx/l2tpv3/l2tpv3.cfg -D 1 -V

echo "selftest: ok"

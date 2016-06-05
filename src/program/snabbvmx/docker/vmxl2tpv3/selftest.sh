#!/bin/bash
tcpdump -n -i xe0 -s 1500 -w /tmp/ip6.pcap ip6 &
sleep 1
tcpreplay -i xe0 -x 8 /u/tagged.pcap
pkill tcpdump
sleep 1
snabb swapipv6 -r /tmp/ipv6.pcap -w /tmp/ipv6-out.pcap -D 1
tcpdump -n -i xe0 -s 1500 -w /tmp/tagged.pcap vlan &
sleep 1
tcpreplay -i xe0 /tmp/ipv6-out.pcap
pkill tcpdump
sleep 1
tcpdump -n -r /u/tagged.pcap -t > /tmp/tagged-orig.txt
tcpdump -n -r /tmp/tagged.pcap -t > /tmp/tagged-new.txt
diff /tmp/tagged-*txt
if [ $? != 0 ]; then
   echo "failed"
else
   echo "ok"
fi


#!/bin/bash
DURATION=5
SNABB="taskset -c 0 ../../../snabb"

PCAP1="b4-icmp-request-1502.pcap"

if [ "$USER" != "root" ]; then
  echo "$0: need to be root. Try again with sudo $0 ..."
  exit 1
fi

grep 'model name' /proc/cpuinfo |head -1

for CONFIG in snabb-port-200k.cfg
#for CONFIG in snabb-port-empty.cfg snabb-port-50k.cfg snabb-port-100k.cfg snabb-port-200k.cfg
do
  for PCAP2 in aftr-icmp-reply-0098.pcap lwaftr-ipv4-50k.pcap
  do
    echo "========================================================="
    echo "Running $CONFIG"
    echo "PCAP files v6:$PCAP1 v4:$PCAP2 ..."
    echo $SNABB lwaftrbench -D $DURATION $CONFIG $PCAP1 $PCAP2 
    $SNABB lwaftrbench -D $DURATION $CONFIG $PCAP1 $PCAP2 
    echo "---------------------------------------------------------"
  done
done
exit

#!/bin/bash
DURATION=5
SNABB=../../../snabb

PCAP1=( b4-icmp-request-0138.pcap )
PCAP2=( aftr-icmp-reply-0098.pcap )
N=${#PCAP1[@]}

if [ "$USER" != "root" ]; then
  echo "$0: need to be root. Try again with sudo $0 ..."
  exit 1
fi

grep 'model name' /proc/cpuinfo |head -1

#for CONFIG in snabb-port-empty.cfg snabb-port-50k.cfg snabb-port-100k.cfg snabb-port-200k.cfg
for CONFIG in snabb-port-empty.cfg 
do
  for (( i=0; i<${N}; i++ ));
  do
    echo "========================================================="
    echo "Running $CONFIG"
    echo "PCAP files v6:${PCAP1[$i]} v4:${PCAP2[$i]} ..."
    echo $SNABB lwaftrbench -D $DURATION $CONFIG ${PCAP1[$i]} ${PCAP2[$i]} 
    taskset -c 0 $SNABB lwaftrbench -D $DURATION $CONFIG ${PCAP1[$i]} ${PCAP2[$i]} 
    echo "---------------------------------------------------------"
  done
done
exit

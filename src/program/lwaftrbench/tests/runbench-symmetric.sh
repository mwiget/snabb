#!/bin/bash
DURATION=30
SNABB=../../../snabb

PCAP1=( b4-icmp-request-0138.pcap b4-icmp-request-0382.pcap b4-icmp-request-1502.pcap )
PCAP2=( aftr-icmp-reply-0098.pcap aftr-icmp-reply-0342.pcap aftr-icmp-reply-1462.pcap )
N=${#PCAP1[@]}

if [ "$USER" != "root" ]; then
  echo "$0: need to be root. Try again with sudo $0 ..."
  exit 1
fi

grep 'model name' /proc/cpuinfo |head -1

for CONFIG in snabb-port-empty.cfg snabb-port-50k.cfg snabb-port-100k.cfg snabb-port-200k.cfg
do
  for (( i=0; i<${N}; i++ ));
  do
    echo "========================================================="
    echo "Running $CONFIG"
    echo "PCAP files v6:${PCAP1[$i]} v4:${PCAP2[$i]} ..."
    echo $SNABB lwaftrbench -D $DURATION $CONFIG ${PCAP1[$i]} ${PCAP2[$i]} 
    $SNABB lwaftrbench -D $DURATION $CONFIG ${PCAP1[$i]} ${PCAP2[$i]} 
    echo "---------------------------------------------------------"
  done
done
exit

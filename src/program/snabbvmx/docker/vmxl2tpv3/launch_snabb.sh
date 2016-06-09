#!/usr/bin/env bash
INT=$1

DEV=$(cat pci_$INT)
CORE=${DEV#*/}
PCI=${DEV%/*}
INTNR=${INT:2:1}
SLEEP=$INTNR

if [ "tap" == "$PCI" ]; then
   NODE=0
else
   CPU=$(cat /sys/class/pci_bus/${PCI%:*}/cpulistaffinity | cut -d'-' -f1 | cut -d',' -f1)
   NODE=$(numactl -H | grep "cpus: $CPU" | cut -d " " -f 2)
fi
NUMACTL="numactl --membind=$NODE --physcpubind=$CORE"

while :
do
  # check if there is a snabb binary available in the mounted directory.
  # use that one if yes
  SNABB=/usr/local/bin/snabb
  if [ -f /u/snabb ]; then
    cp /u/snabb / 2>/dev/null
    SNABB=/snabb
  fi

  echo "launch snabbvmx for $INT on cpu $CORE (node $NODE) after $SLEEP seconds ..."
  if [ "tap" == "$PCI" ]; then
    CMD="$NUMACTL $SNABB snabbvmx l2tpv3 --conf snabbvmx-l2tpv3-${INT}.cfg --id $INT --tap $INT --mac `cat mac_$INT` --sock %s.socket"
  else
    CMD="$NUMACTL $SNABB snabbvmx l2tpv3 --conf snabbvmx-l2tpv3-${INT}.cfg --id $INT --pci $PCI --mac `cat mac_$INT` --sock %s.socket"
  fi
  echo $CMD
  sleep $SLEEP
  $CMD
  $SNABB gc # removing stale runtime files created by Snabb
  sleep 2
done

#!/usr/bin/env bash

echo "selftest: packetblaster"
export PCIADDR=$SNABB_PCI_INTEL0
[ ! -z "$PCIADDR" ] || export PCIADDR=$SNABB_PCI0
if [ -z "${PCIADDR}" ]; then
    echo "selftest: skipping test - SNABB_PCI_INTEL0/SNABB_PCI0 not set"
    exit 43
fi
 
# Simple test: Just make sure packetblaster runs for a period of time
# (doesn't crash on startup).
timeout 5 ./snabb packetblaster replay program/snabbnfv/test_fixtures/pcap/64.pcap ${PCIADDR}
status=$?
if [ $status != 124 ]; then
    echo "Error: expected timeout (124) but got ${status}"
    exit 1
fi

timeout 5 ./snabb packetblaster synth --src 11:11:11:11:11:11 --dst 22:22:22:22:22:22 --sizes 64,128,256 ${PCIADDR}
status=$?
if [ $status != 124 ]; then
    echo "Error: expected timeout (124) but got ${status}"
    exit 1
fi

echo "selftest: ok"

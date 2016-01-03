#!/bin/bash
# Modified from Diego's end-to-end benchmarking script

SNABB_SRC=../../../..
TEST_BASE=../data
TEST_OUT=/tmp
EMPTY=${TEST_BASE}/empty.pcap

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

function quit_with_msg {
   echo $1; exit 1
}

function usage {
    quit_with_msg "Usage: benchmark-pcaps v4.pcap v6.pcap <pcidev_v4> <pcidev_v6>"
}

v4_pcap=$1
v6_pcap=$2
pcidev_v4=$3
pcidev_v6=$4
if [ -z "$pcidev_v6" ]; then
    usage
fi

function run_benchmark {
    local script=${SNABB_SRC}/apps/lwaftr/benchmark.lua
    local conf=$1
    local pcap_file_v4=$2
    local pcap_file_v6=$3

    ${SNABB_SRC}/snabb snsh $script $conf $pcap_file_v4 $pcap_file_v6 $pcidev_v4 $pcidev_v6
}

echo "Benchmarking..."
run_benchmark ${TEST_BASE}/icmp_on_fail.conf $v4_pcap $v6_pcap

#!/usr/bin/env bash
NAME="vmx1"
OPTIONS="-P 5 -m 4000"
CFG="vmx1.txt"
IMG="vmx-15.1F5-S1.5.tgz"
IDENTITY="snabbvmx.key"
INTERFACES="tap/6 tap/7 tap/8 tap/9"
LICENSE="license-eval.txt"
#LICENSE="license-unlimited.txt"
echo "Launching vMX with $INTERFACES and options $OPTIONS ..."
docker rm $NAME >/dev/null 2>/dev/null
rm -f snabb >/dev/null 2>/dev/null
#docker pull marcelwiget/vmxl2tpv3
docker run --name $NAME -ti --privileged -v $PWD:/u:ro marcelwiget/vmxl2tpv3 -i $IDENTITY -c $CFG -l $LICENSE $DEBUG $OPTIONS $IMG $INTERFACES

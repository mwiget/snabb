#!/usr/bin/env bash
NAME="vmx2"
OPTIONS="-P 5 -m 4000"
CFG="vmx2.txt"
IMG="vmx-15.1F5-S1.5.tgz"
IDENTITY="snabbvmx.key"
chmod 400 $IDENTITY
INTERFACES="0000:05:00.0/6 0000:05:00.1/6"
LICENSE="license-eval.txt"
#LICENSE="license-unlimited.txt"
echo "Launching vMX with $INTERFACES and options $OPTIONS ..."
docker rm $NAME >/dev/null 2>/dev/null
rm -f snabb >/dev/null 2>/dev/null
#docker pull marcelwiget/vmxl2tpv3
docker run --name $NAME -ti --privileged -v $PWD:/u:ro marcelwiget/vmxl2tpv3 -i $IDENTITY -c $CFG -l $LICENSE $DEBUG $OPTIONS $IMG $INTERFACES

#!/usr/bin/env bash
VERSION="latest"
cp ../../../../snabb .
#docker build --no-cache -t marcelwiget/vmxl2tpv3:$VERSION .
docker build -t marcelwiget/vmxl2tpv3:$VERSION .

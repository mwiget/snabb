#!/usr/bin/env bash
PORT="${1:-xe0}"
while :
do
  SNABB_PID=$(ps ax |grep $PORT | grep l2tpv3|grep id|head -1|awk '{print $1}')
  if [ ! -z "$SNABB_PID" ]; then
    snabb snabbvmx top3 $SNABB_PID
  fi
  echo "waiting for snabb on $PORT ..."
  sleep 1
done

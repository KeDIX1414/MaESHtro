#!/bin/sh

#  PingTest.sh
#  Run with 2 arguments, first is number of "Pis" you want to run concurrently,
#  second is number of packets to send
#
#  Created by Nour Hussein on 4/1/18.
#
counter=1
numSpawns=$1
numPackets=$2
while [ $counter -le $numSpawns ]
do
    echo $counter$(ping 172.217.15.100 -c $numPackets | grep 'rtt')&
    ((counter++))
done


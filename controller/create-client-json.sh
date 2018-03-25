#!/bin/bash

#Begin JSON file with curly bracket
echo "{" > client-neighbors.json

#Find my own IP addres, create my-neighbors file, and write my IP to it
MY_IP="$(sed -n -e 's/^.*address //p' /etc/network/interfaces)"
echo "'my_ip': '${MY_IP}'," >> client-neighbors.json


#Check if this is a gateway node (can ping google). If so, set gatway flag to True
PING_OUTPUT="$(ifconfig | grep "wlan1")"

if ! [ -z "$PING_OUTPUT" ]; then 
	echo "'is_gateway': True," >> client-neighbors.json
else 
	echo "'is_gateway': False," >> client-neighbors.json
fi 

#Manually ping each possible neighbor IP and add if reachable 
#TODO: Add your range of IPs you'd like to ping here
echo "'neighbors': [" >> client-neighbors.json

PING_OUTPUT="$(ping -c 1 6.6.1.5 | grep "1 received")"

if ! [ -z "$PING_OUTPUT" ]; then 
	echo "'6.6.1.5'" >> client-neighbors.json
fi 

echo "]" >> client-neighbors.json

#End JSON file with curly bracket
echo "}" >> client-neighbors.json

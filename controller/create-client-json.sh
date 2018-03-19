#!/bin/bash

#Begin JSON file with curly bracket
echo "{" > client-neighbors.json

#Find my own IP addres, create my-neighbors file, and write my IP to it
MY_IP="$(hostname -i)"
echo "'my_ip': '${MY_IP}'," >> client-neighbors.json


#Check if this is a gateway node (can ping google). If so, set gatway flag to True
PING_OUTPUT="$(ping -c 1 www.google.com | grep "1 packets received")"

if ! [ -z "$PING_OUTPUT" ]; then 
	echo "'is_gateway': True," >> client-neighbors.json
else 
	echo "'is_gateway': False," >> client-neighbors.json
fi 

#Manually ping each possible neighbor IP and add if reachable 
echo "'neighbors': [" >> client-neighbors.json

PING_OUTPUT="$(ping -c 1 www.facebook.com | grep "1 packets received")"

if ! [ -z "$PING_OUTPUT" ]; then 
	echo "'www.facebook.com'," >> client-neighbors.json
fi 

PING_OUTPUT="$(ping -c 1 www.reddit.com | grep "1 packets received")"

if ! [ -z "$PING_OUTPUT" ]; then 
	echo "'www.reddit.com'" >> client-neighbors.json
fi 

echo "]" >> client-neighbors.json

#Begin JSON file with curly bracket
echo "}" >> client-neighbors.json
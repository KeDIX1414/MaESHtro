#!/bin/bash

#Find my own IP addres, create my-neighbors file, and write my IP to it
MY_IP="$(hostname -i)"
echo "${MY_IP}" > my-neighbors


#Ping an address, if successful write that IP address to my-neighbors file
PING_OUTPUT="$(ping -c 1 www.google.com | grep "1 packets received")"

if ! [ -z "$PING_OUTPUT" ]; then 
	echo "www.google.com" >> my-neighbors
fi 

PING_OUTPUT="$(ping -c 1 www.facebook.com | grep "1 packets received")"

if ! [ -z "$PING_OUTPUT" ]; then 
	echo "www.facebook.com" >> my-neighbors
fi 

PING_OUTPUT="$(ping -c 1 www.reddit.com | grep "1 packets received")"

if ! [ -z "$PING_OUTPUT" ]; then 
	echo "www.reddit.com" >> my-neighbors
fi 
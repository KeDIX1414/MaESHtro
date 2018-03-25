#!/bin/bash

#grabs the ipv4 address of the specified interface (wlan1 in this case)
echo $(ifconfig wlan1 | grep 'inet ' | awk '{print $2}')

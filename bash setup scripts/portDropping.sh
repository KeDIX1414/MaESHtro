#!/bin/bash

#kill incoming ports kernel processing

#kills port 4
sudo iptables -t raw -A PREROUTING -p tcp --dport 4 -j DROP

#kills port 8
#sudo iptables -t raw -A PREROUTING -p tcp --dport 8 -j DROP

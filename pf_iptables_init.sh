#!/bin/sh

##  to do

iptables -I OUTPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 11220
iptables -I INPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 11221

#!/bin/sh

##  to do

iptables -A OUTPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 11220
iptables -A INPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 11221

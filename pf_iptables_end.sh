#!/bin/sh

##  to do

iptables -D OUTPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 11220
iptables -D INPUT -m conntrack --ctstate NEW -j NFQUEUE --queue-num 11221

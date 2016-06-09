#!/bin/sh

## to do

iptables -D OUTPUT -m iprange --dst-range 127.0.0.0-127.255.255.255 -j ACCEPT
iptables -D INPUT -m iprange --dst-range 127.0.0.0-127.255.255.255 -j ACCEPT

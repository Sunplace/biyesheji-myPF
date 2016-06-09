#!/bin/sh

## to do

iptables -I OUTPUT -m iprange --dst-range 127.0.0.0-127.255.255.255 -j ACCEPT
iptables -I INPUT -m iprange --dst-range 127.0.0.0-127.255.255.255 -j ACCEPT

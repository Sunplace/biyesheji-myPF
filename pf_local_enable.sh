#!/bin/sh

## to do

iptables -A OUTPUT -m iprange --dst-range 127.0.0.0-127.255.255.255 -j ACCEPT
iptables -A INPUT -m iprange --dst-range 127.0.0.0-127.255.255.255 -j ACCEPT

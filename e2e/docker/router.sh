#!/bin/sh
# A NAT router like a home router or a libvirt host: masquerades the LAN behind its address
set -eu
lan_if=$(ip -o -4 addr show | awk '/192\.168\.50\./ {print $2}')
wan_if=$(ip -o -4 addr show | awk '/198\.51\.100\./ {print $2}')
iptables -t nat -A POSTROUTING -s 192.168.50.0/24 -o "$wan_if" -j MASQUERADE
iptables -A FORWARD -i "$lan_if" -o "$wan_if" -j ACCEPT
iptables -A FORWARD -i "$wan_if" -o "$lan_if" -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -P FORWARD DROP
echo "router: $lan_if -> $wan_if"
exec sleep infinity

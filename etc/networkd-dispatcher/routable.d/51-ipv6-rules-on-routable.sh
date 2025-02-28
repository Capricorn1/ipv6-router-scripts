#!/bin/bash

# This script calls another script that applies the firewall rules for IPV6 
# when the system (re)enters the routable network state. See man networkctl
# for a list of network states and their meaning.

# This script is called once per network interface. In a router with both a WAN 
# NIC and LAN NIC, this scrpt is called twice. We limit it using the $IFACE
# environment variable to being called only when the WAN interface becomes 
# routable. 

echo "Entering script that sets the firewall rules for IPv6 interfaces"

WAN_INTERFACE="enp2s0"

if [ -z "$IFACE" ]
then
        echo "\$IFACE environment variable was empty. Skipping rule application for IPv6 rules"
else
        if [ "$IFACE" == "$WAN_INTERFACE" ]
        then
                echo "WAN interface $IFACE routable on IPv6. Applying IPv6 rules."
                source /opt/iptables/rules-dhcp-ip-from-shell.v6.sh
        else
                echo "Called for interface $IFACE rather than $WAN_INTERFACE. Skipping."
        fi
fi

echo "Exiting firewall rules script for IPv6 interfaces"


#!/bin/bash

# This script calls another script that applies the firewall rules for IPV4
# when the system (re)enters the routable network state. See man networkctl
# for a list of network states and their meaning.

# This script is called once per network interface. In a router with both a WAN
# NIC and LAN NIC, this script is called twice. We limit it using the $IFACE
# environment variable to being called only when the WAN interface becomes
# routable.

echo "Entering script that sets the firewall rules for IPv4 interfaces"

WAN_INTERFACE="enp2s0"

if [ -z "$IFACE" ]
then
        echo "\$IFACE environment variable was empty. Skipping rule application for IPv4 rules"
else
        if [ "$IFACE" == "$WAN_INTERFACE" ]
        then
                echo "WAN interface $IFACE routable on IPv4. Applying IPv4 rules."
                source /opt/iptables/rules-dhcp-ip-from-shell.v4.sh
        else
                echo "Called for interface $IFACE rather than $WAN_INTERFACE. Skipping."
        fi
fi

echo "Exiting firewall rules script for IPv4 interfaces"


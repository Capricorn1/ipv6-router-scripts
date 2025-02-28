#!/bin/bash

# This script calls another script that examines the current prefix delegation 
# and sets the WAN and LAN IP addresses accordingly. It is called whenever the
# system (re)enters the routable network state. See man networkctl for a list 
# of network states and their meaning.

# NOTE! This script should be called before any others as all of the others 
# rely on the IP addresses set when this script runs.

# This script is called once per network interface. In a router with both a WAN
# NIC and LAN NIC, this script is called twice. We limit it using the $IFACE
# environment variable to being called only when the WAN interface becomes
# routable.

echo "Entering set IPv6 addresses for each network interface"

WAN_INTERFACE="enp2s0"

if [ -z "$IFACE" ]
then
        echo "\$IFACE environment variable was empty. Skipping configuration of the IPv6 addresses"
else
        if [ "$IFACE" == "$WAN_INTERFACE" ]
        then
                echo "WAN interface $IFACE entered routable mode. Configuring IPv6 WAN and LAN addresses."
                source /opt/ipv6-configuration/ipv6-compute-and-configure.sh
        else
                echo "Called for interface $IFACE rather than $WAN_INTERFACE. Skipping."
        fi
fi

echo "Exiting set IPv6 addresses for each network interface"


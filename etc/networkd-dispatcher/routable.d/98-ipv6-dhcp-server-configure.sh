#!/bin/bash

# This script calls another script that sets up the DHCP6 server for the LAN
# side of the network.

# To prevent running this script for all interfaces, we limit it to run for
# only one of the interfaces becoming routable. Originally, the LAN interface
# made more sense, but in practice, the LAN interface is initialized first -
# before the WAN interface had gotten the latest prefix delegation.

echo "Enter script to configure the DHCP6 server for the IPv6 LAN interface."

# WAN Interface ID
MONITORED_INTERFACE="enp2s0"

if [ -z "$IFACE" ]
then
        echo "\$IFACE environment variable was empty. Skipping configuration of the DHCP6 server for the LAN interface."
else
        if [ "$IFACE" == "$MONITORED_INTERFACE" ]
        then
                echo "The monitored interface, $IFACE, entered the routable state. Configuring the IPv6 DHCP6 on the LAN interface."
                source /opt/ipv6-configuration/dhcp6-server-configure.sh
        else
                echo "Called for interface $IFACE rather than $MONITORED_INTERFACE. Skipping."
        fi
fi

echo "Exiting script to configure the DHCP6 server for the IPv6 LAN interface."


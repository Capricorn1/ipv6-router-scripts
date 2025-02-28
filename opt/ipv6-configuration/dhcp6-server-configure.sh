#!/bin/bash

# This script expects the IPv6 WAN IP has already been set on the WAN interface.
# We will test to make sure that it exists before going on. This takes care of 
# an issue where the networkd-dispatcher call this script several seconds 
# before it does the same for the WAN interface. 

# This script expects the IPv6 LAN IP has already been set on the LAN 
# Interface. It will extact the prefix portion from it, edit a templated 
# version of the kea-dhcp6.conf file with that prefix, and save the edited
# version in the Kea DHCP directory.

# The device ID of the WAN Ethernet interface
WAN_IF="enp2s0"

# The device ID of the LAN Ethernet interface
LAN_IF="enp4s0"

# The directory location of the DHCP6 configuration template
DHCP_CONF_TEMPLATE_DIR="/opt/ipv6-configuration/"

# The file name of the DHCP6 configuration template
DHCP_CONF_TEMPLATE_FILE="kea-dhcp6.conf.template"

# The directory location of the edited DHCP6 configuration
DHCP_CONF_DIR="/etc/kea/"
# DHCP_CONF_DIR="/tmp/"

# The file name of the edited DHCP6 configuration
DHCP_CONF_FILE="kea-dhcp6.conf"

# DHCP Lease file directory
DHCP_LEASE_DIR="/var/lib/kea/"

# DHCP6 Lease file pattern
DHCP6_LEASE_FILE_PATTERN="kea-leases6.csv*"

# DHCP6 server shutdown/startup delay in seconds
DHCP_CYCLE_DELAY=5

# The WAN IP needs to be established before we go on.
# First, we verify that address was set by an earlier configuration script.
CURRENT_WAN_IP=""
IP_ADDR_RETRY_COUNT=0              # Current IP Address DHCP resolution retry count
IP_ADDR_RETRY_MAX=2                # Maximum number of times to retry before giving up
IP_ADDR_RETRY_SLEEP_TIME=10        # Seconds to sleep between retrys

getIpv6ExternalIPAddress() {
	CURRENT_WAN_IP=$(/sbin/ip -o -6 addr list $WAN_IF | egrep -v fe80 | awk '{print $4}');
    IP_ADDR_RETRY_COUNT=$((IP_ADDR_RETRY_COUNT+1))
}

getIpv6ExternalIPAddress
while [ -z "$CURRENT_WAN_IP" -a $IP_ADDR_RETRY_COUNT -le $IP_ADDR_RETRY_MAX ]; do
    echo "WAN IPv6 IP address not yet known. Sleeping for $IP_ADDR_RETRY_SLEEP_TIME seconds."
	sleep $IP_ADDR_RETRY_SLEEP_TIME;
	getIpv6ExternalIPAddress
done

if [ -z "$CURRENT_WAN_IP" ]; then
    echo "WAN IPv6 IP address not resolved. Exiting."
    exit 1
fi
# We don't need the WAN IP address for anything. We just need for it to be set before 
# continuing.

# The LAN IP can be any of the other 254 available /64 subnets. 
# First, we verify that address was set by an earlier configuration script.
CURRENT_LAN_IP=$(/sbin/ip -o -6 addr list $LAN_IF | egrep -v fe80 | awk '{print $4}')

if [ -z "$CURRENT_LAN_IP" ]; then
    echo "Current LAN IP was not found"
	echo "This script will now exit"
	exit 1
fi

# Now, we get the LAN subnet prefix to use in our edits
LAN_SUBNET_SANS_PREFIX=`ip -6 route list dev ${LAN_IF} | egrep -v "fe80" | awk '{print $1}' | awk -F "/" '{print $1}'`
echo "Current LAN prefix (sans mask): $LAN_SUBNET_SANS_PREFIX"

echo "Editing $DHCP_CONF_TEMPLATE_DIR$DHCP_CONF_TEMPLATE_FILE and streaming the result into $DHCP_CONF_DIR$DHCP_CONF_FILE."

$( /usr/bin/sed -e "s/XXXX\:XXXX\:XXXX\:XXXX\:\:/${LAN_SUBNET_SANS_PREFIX}/g" $DHCP_CONF_TEMPLATE_DIR$DHCP_CONF_TEMPLATE_FILE > $DHCP_CONF_DIR$DHCP_CONF_FILE )

echo "Changing the ownership and file mode of $DHCP_CONF_DIR$DHCP_CONF_FILE."
$( /usr/bin/chmod 664 $DHCP_CONF_DIR$DHCP_CONF_FILE )
$( /usr/bin/chown "root:_kea" $DHCP_CONF_DIR$DHCP_CONF_FILE )

echo "Stopping the Kea DHCP6 Server"
$( /usr/bin/systemctl stop kea-dhcp6-server )
sleep $DHCP_CYCLE_DELAY

echo "Removing the lease files $DHCP_LEASE_DIR$DHCP6_LEASE_FILE_PATTERN."
/usr/bin/rm ${DHCP_LEASE_DIR}${DHCP6_LEASE_FILE_PATTERN}

echo "Restarting the Kea DHCP6 server"
$( /usr/bin/systemctl start kea-dhcp6-server )
sleep $DHCP_CYCLE_DELAY

DHCP6_SERVER_STATUS=$( /usr/bin/systemctl status kea-dhcp6-server )
echo "DHCP6 Server Status: "
echo "${DHCP6_SERVER_STATUS}"

exit 0

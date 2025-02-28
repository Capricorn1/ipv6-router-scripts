#!/bin/bash

# This script expects the IPv6 WAN IP has already been set on the WAN interface.
# We will test to make sure that it exists before going on. This takes care of
# an issue where the networkd-dispatcher call this script several seconds
# before it does the same for the WAN interface.

# This script expects the IPv6 LAN IP has already been set on the LAN 
# Interface. It will extact the prefix portion from it, edit a templeted 
# version of several DNS zone files for the local-caching DNS server.

# The device ID of the WAN Ethernet interface
WAN_IF="enp2s0"

# The device ID of the LAN Ethernet interface
LAN_IF="enp4s0"

# The directory location of the DNS configuration templates
DNS_CONF_TEMPLATES_DIR="/opt/ipv6-configuration"

# The file name of the template for the db.home.zone file
DNS_HOME_ZONE_TEMPLATE_FILE="db.home.zone.template"

# The file name of the template for reverse zone file
DNS_REVERSE_ZONE_TEMPLATE_FILE="db.reverse.ipv6.arpa.zone.template"

# The file name of the template for named.conf.local template file
DNS_NAMED_CONF_LOCAL_TEMPLATE_FILE="named.conf.local.template"

# The target directory location of the edited DNS configuration files
DNS_CONF_DIR="/etc/bind"
DNS_CONF_DIR_EXPR="\/etc\/bind"
# DNS_CONF_DIR="/tmp"
# DNS_CONF_DIR_EXPR="\/tmp"

# The file name for the db.home.zone file
DNS_HOME_ZONE_FILE="db.home.zone"

# The file name for the reverse DNS zone file
DNS_REVERSE_ZONE_FILE=""

# The file name for the named.conf.local file
DNS_NAMED_CONF_LOCAL_FILE="named.conf.local"

# DNS server shutdown/startup delay in seconds
DNS_SERVER_CYCLE_DELAY=5

# The WAN IP needs to be established before we go on.
# First, we verify that address was set by an earlier configuration script.
CURRENT_WAN_IP=""
IP_ADDR_RETRY_COUNT=0              # Current IP Address DNS resolution retry count
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

# Generate a new serial number for use in all of the edited files
GENERATED_SERIAL=`date +"%Y%m%d%H"`
echo "GENERATED_SERIAL: ${GENERATED_SERIAL}"

# Join the LAN subnet hexadecimal number sans colons and with leading zero 
# padding as needed
PADDED_LAN_SUBNET_SANS_PREFIX=""
for((i=1; i<=4; i++)); do
    CURRENT_HEXTET=`echo ${LAN_SUBNET_SANS_PREFIX} | awk -F\: -v hexNum=${i} '{print $hexNum}'`;
    HEXTET_LEN=${#CURRENT_HEXTET}
    if [ $HEXTET_LEN -lt 4 ]; then
        for((j=$HEXTET_LEN; j<4; j++)); do
            PADDED_LAN_SUBNET_SANS_PREFIX="${PADDED_LAN_SUBNET_SANS_PREFIX}0";
        done
    fi
    PADDED_LAN_SUBNET_SANS_PREFIX="${PADDED_LAN_SUBNET_SANS_PREFIX}${CURRENT_HEXTET}";
done

echo "Final padded LAN subnet: ${PADDED_LAN_SUBNET_SANS_PREFIX}"

# Reverse the string and inject periods between the charaters (but not before 
# or after the string)
REVERSED_LAN_SUBNET=""

COPY=${PADDED_LAN_SUBNET_SANS_PREFIX}

LEN=${#COPY}
for((i=$LEN-1; i>=0; i--)); do 
    REVERSED_LAN_SUBNET="${REVERSED_LAN_SUBNET}${COPY:$i:1}"; 
    if [ $i -gt 0 ]; then
        REVERSED_LAN_SUBNET="${REVERSED_LAN_SUBNET}.";
    fi
done
echo "REVERSED_LAN_SUBNET: ${REVERSED_LAN_SUBNET}"
# We now have the dot notation string to use for the IPV6 reverse DNS file. 

# Edit the home zone file with the IPv6 LAN subnet (without the /64 prefix) into 
# the home zone file template (along with the generated serial number).
echo "Editing $DNS_CONF_TEMPLATES_DIR/$DNS_HOME_ZONE_TEMPLATE_FILE and streaming the result into $DNS_CONF_DIR/$DNS_HOME_ZONE_FILE."
$( /usr/bin/sed -e "s/GENERATED_SERIAL/${GENERATED_SERIAL}/g" -e "s/IPV6_PREFIX_64\:\:/${LAN_SUBNET_SANS_PREFIX}/g" $DNS_CONF_TEMPLATES_DIR/$DNS_HOME_ZONE_TEMPLATE_FILE > $DNS_CONF_DIR/$DNS_HOME_ZONE_FILE )

# Edit the IPv6 reverse DNS template file by injecting the generated serial 
# number and writing the results to the computed file name.
DNS_REVERSE_ZONE_FILE="db.${REVERSED_LAN_SUBNET}.ip6.arpa.zone"
echo "DNS_REVERSE_ZONE_FILE: ${DNS_REVERSE_ZONE_FILE}"
echo "Editing $DNS_CONF_TEMPLATES_DIR/$DNS_REVERSE_ZONE_TEMPLATE_FILE and streaming the result into $DNS_CONF_DIR/$DNS_REVERSE_ZONE_FILE"
$( /usr/bin/sed -e "s/GENERATED_SERIAL/${GENERATED_SERIAL}/g" $DNS_CONF_TEMPLATES_DIR/$DNS_REVERSE_ZONE_TEMPLATE_FILE > $DNS_CONF_DIR/$DNS_REVERSE_ZONE_FILE )

# Edit the named.conf.local template file with the DNS configuration directory 
# and the reversed LAN subnet dot notation
echo "Editing $DNS_CONF_TEMPLATES_DIR/$DNS_NAMED_CONF_LOCAL_TEMPLATE_FILE and streaming the result into $DNS_CONF_DIR/$DNS_NAMED_CONF_LOCAL_FILE"
# $( /usr/bin/sed -e "s/REVERSED_LAN_SUBNET/${REVERSED_LAN_SUBNET}/g" $DNS_CONF_TEMPLATES_DIR/$DNS_NAMED_CONF_LOCAL_TEMPLATE_FILE > $DNS_CONF_DIR/$DNS_NAMED_CONF_LOCAL_FILE )
SECOND_EDIT_EXPR="s/DNS_CONF_DIR/${DNS_CONF_DIR_EXPR}/g"
echo "SECOND_EDIT_EXPR: ${SECOND_EDIT_EXPR}"

$( /usr/bin/sed -e "s/REVERSED_LAN_SUBNET/${REVERSED_LAN_SUBNET}/g" -e "${SECOND_EDIT_EXPR}" $DNS_CONF_TEMPLATES_DIR/$DNS_NAMED_CONF_LOCAL_TEMPLATE_FILE > $DNS_CONF_DIR/$DNS_NAMED_CONF_LOCAL_FILE )

# Change the mode and ownership of the edited files.
echo "Changing the ownership and file mode of $DNS_CONF_DIR/$DNS_HOME_ZONE_FILE, $DNS_CONF_DIR/$DNS_REVERSE_ZONE_FILE, and $DNS_CONF_DIR/$DNS_NAMED_CONF_LOCAL_FILE"
$( /usr/bin/chmod 664 $DNS_CONF_DIR/$DNS_HOME_ZONE_FILE $DNS_CONF_DIR/$DNS_REVERSE_ZONE_FILE $DNS_CONF_DIR/$DNS_NAMED_CONF_LOCAL_FILE )
$( /usr/bin/chown "root:bind"  $DNS_CONF_DIR/$DNS_HOME_ZONE_FILE $DNS_CONF_DIR/$DNS_REVERSE_ZONE_FILE $DNS_CONF_DIR/$DNS_NAMED_CONF_LOCAL_FILE )

# Restart the local DNS server
echo "Stopping the DNS Server"
$( /usr/bin/systemctl stop named.service )
sleep $DNS_SERVER_CYCLE_DELAY

echo "Starting the DNS server"
$( /usr/bin/systemctl start named.service )
sleep $DNS_SERVER_CYCLE_DELAY

DNS_SERVER_STATUS=$( /usr/bin/systemctl status named.service )
echo "DNS Server Status: "
echo "${DNS_SERVER_STATUS}"

exit 0

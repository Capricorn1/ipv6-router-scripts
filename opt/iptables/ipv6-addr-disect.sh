#!/bin/bash

#
######################################################################
# WAN side definitions (dynamically created)
######################################################################
INTERNET_IF="enp2s0"                   # WAN (Internet) interface (NIC) device name
echo '    Internet interface: '\'$INTERNET_IF\'
logger "$(basename "$0"): Internet inteface: $INTERNET_IF"

INTERNET_SUBNET=""
IP_ADDR_RETRY_COUNT=0           # Current IP Address DHCP resolution retry count
IP_ADDR_RETRY_MAX=20            # Maximum number of times to retry before giving up
IP_ADDR_RETRY_SLEEP_TIME=10     # Seconds to sleep between retrys

getIpv6Address() {
        INTERNET_SUBNET=$(/sbin/ip -o -6 addr list $INTERNET_IF | egrep -v fe80 | awk '{print $4}')
        IP_ADDR_RETRY_COUNT=$((IP_ADDR_RETRY_COUNT+1))
}

getIpv6Address
while [ -z "$INTERNET_SUBNET" -a $IP_ADDR_RETRY_COUNT -le $IP_ADDR_RETRY_MAX ]; do
        echo "Internet IPv6 subnet and IPv6 IP address not yet known. Sleeping for $IP_ADDR_RETRY_SLEEP_TIME seconds."
        sleep $IP_ADDR_RETRY_SLEEP_TIME # Sleep for 10 seconds
        getIpv6Address
done

if [ -z "$INTERNET_SUBNET" ]; then
    echo "Internet IPv6 subnet and IPv6 IP address not resolved. Exiting."
    logger "$(basename "$0"): Internet IPv6 subnet and IPv6 IP address not resolved. Exiting."
    exit 0
fi
echo '       INTERNET_SUBNET: '\'$INTERNET_SUBNET\'
logger "$(basename "$0"): Internet subnet: $INTERNET_SUBNET"

# Our publicly visible IP address on that net
INTERNET_IP=$(/sbin/ip -o -6 addr list $INTERNET_IF | egrep -v fe80 | awk '{print $4}' | cut -d/ -f1)
echo '           INTERNET_IP: '\'$INTERNET_IP\'
logger "$(basename "$0"): Internet IP: $INTERNET_IP"

# Our subnet prefix length
INTERNET_PREFIX_LENGTH=$(/sbin/ip -o -6 addr list $INTERNET_IF | egrep -v fe80 | awk '{print $4}' | cut -d/ -f2)
echo 'INTERNET_PREFIX_LENGTH: '\'$INTERNET_PREFIX_LENGTH\'
logger "$(basename "$0"): Internet Prefix Length: $INTERNET_PREFIX_LENGTH"

# Fetch our IPv6 address using the sipcalc package
# IPV6_INFO=$(sipcalc $INTERNET_SUBNET)
# echo '             IPv6 info: '\'$IPV6_INFO\'
# logger "$(basename "$0"): IPv6 info: $IPV6_INFO"

# Our subnet prefix
INTERNET_SUBNET_PREFIX1=$(/sbin/ip -6 route list dev enp2s0 | egrep -v "fe80" | awk '{print $1}')
echo 'INTERNET_SUBNET_PREFIX1: '\'$INTERNET_SUBNET_PREFIX1\'
logger "$(basename "$0"): Internet subnet prefix from ip: $INTERNET_SUBNET_PREFIX1"
INTERNET_SUBNET_PREFIX2=$(sipcalc $INTERNET_SUBNET | fgrep 'Subnet prefix' | cut -d '-' -f 2 | tr -d ' ')
echo 'INTERNET_SUBNET_PREFIX2: '\'$INTERNET_SUBNET_PREFIX2\'
logger "$(basename "$0"): Internet subnet prefix from sipcalc: $INTERNET_SUBNET_PREFIX2"

# Our address ID
INTERNET_ADDRESS_ID=$(sipcalc $INTERNET_SUBNET | fgrep 'Address ID' | cut -d '-' -f 2 | tr -d ' ')
echo '   INTERNET_ADDRESS_ID: '\'$INTERNET_ADDRESS_ID\'
logger "$(basename "$0"): Internet address ID: $INTERNET_ADDRESS_ID"

echo ""

######################################################################
# Link Local Subnet on External Interface (dynamically created)
######################################################################
EXT_LINKLOCAL_SUBNET=$(/sbin/ip -o -6 addr list $INTERNET_IF | egrep fe80 | awk '{print $4}')
if [ -z "$EXT_LINKLOCAL_SUBNET" ]; then
    echo "Link local IPv6 subnet and IPv6 IP address not yet known. Exiting."
    logger "$(basename "$0"): Link local IPv6 subnet and IPv6 IP address on external interface not yet known. Exiting."
    exit 0
fi
echo '  EXT_LINKLOCAL_SUBNET: '\'$EXT_LINKLOCAL_SUBNET\'
logger "$(basename "$0"): Ext Link local subnet: $EXT_LINKLOCAL_SUBNET"

EXT_LINKLOCAL_IP=$(/sbin/ip -o -6 addr list $INTERNET_IF | egrep fe80 | awk '{print $4}' | cut -d/ -f1)
echo '      EXT_LINKLOCAL_IP: '\'$EXT_LINKLOCAL_IP\'
logger "$(basename "$0"): Ext Link local IP: $EXT_LINKLOCAL_IP"

EXT_INTERNET_GATEWAY=$EXT_LINKLOCAL_SUBNET
echo '  EXT_INTERNET_GATEWAY: '\'$EXT_INTERNET_GATEWAY\'
logger "$(basename "$0"): Ext Gateway IP: $EXT_INTERNET_GATEWAY"

echo ""

######################################################################
# LAN side definitions (static on the firewall itself)
######################################################################

LAN_IF="enp4s0"             		# WAN (Internet) interface (NIC) device name
echo '(IPv6)     LAN interface: '\'$LAN_IF\'
logger "$(basename "$0"):(IPv6) LAN inteface: $LAN_IF"

LAN_IP=""
IP_ADDR_RETRY_COUNT=0              	# Current IP Address DHCP resolution retry count
IP_ADDR_RETRY_MAX=2            		# Maximum number of times to retry before giving up
IP_ADDR_RETRY_SLEEP_TIME=10   		# Seconds to sleep between retrys

getIpv6InternalIPAddress() {
    LAN_IP=$(/sbin/ip -o -6 addr list $LAN_IF | egrep -v fe80 | awk '{print $4}')
    IP_ADDR_RETRY_COUNT=$((IP_ADDR_RETRY_COUNT+1))
}

getIpv6InternalIPAddress
while [ -z "$LAN_IP" -a $IP_ADDR_RETRY_COUNT -le $IP_ADDR_RETRY_MAX ]; do
        echo "(IPv6)LAN IPv6 IP address not yet known. Sleeping for $IP_ADDR_RETRY_SLEEP_TIME seconds."
    sleep $IP_ADDR_RETRY_SLEEP_TIME
    getIpv6InternalIPAddress
done

if [ -z "$LAN_IP" ]; then
    echo "(IPv6)LAN IPv6 IP address not resolved. Exiting."
    logger "$(basename "$0")(IPv6): LAN IPv6 IP address not resolved. Exiting."
    exit 0
fi

echo '(IPv6)            LAN_IP: '\'$LAN_IP\'
logger "$(basename "$0")(IPv6): Internet IP: $LAN_IP"

# Our LAN IP without the mask
LAN_IP_SANS_MASK=$(echo $LAN_IP | cut -d/ -f1)
echo '(IPv6)  LAN_IP_SANS_MASK: '\'$LAN_IP_SANS_MASK\'
logger "$(basename "$0")(IPv6): LAN IP sans mask: $LAN_IP_SANS_MASK"

# Our subnet prefix length
LAN_PREFIX_LENGTH=$(/sbin/ip -o -6 addr list $LAN_IF | egrep -v fe80 | awk '{print $4}' | cut -d/ -f2)
echo '(IPv6) LAN_PREFIX_LENGTH: '\'$LAN_PREFIX_LENGTH\'
logger "$(basename "$0")(IPv6): Internet Prefix Length: $LAN_PREFIX_LENGTH"

# Fetch our LAN IPv6 address using the sipcalc package
IPV6_LAN_INFO=$(sipcalc $LAN_IP)
# echo '(IPv6)             IPv6 info: '\'$IPV6_LAN_INFO\'
# logger "$(basename "$0")(IPv6): IPv6 info: $IPV6_LAN_INFO"

# Our LAN subnet prefix
LAN_SUBNET=$(sipcalc $LAN_IP | fgrep 'Subnet prefix' | cut -d '-' -f 2 | tr -d ' ')
echo '(IPv6)        LAN_SUBNET: '\'$LAN_SUBNET\'
logger "$(basename "$0")(IPv6): Internet subnet prefix: $LAN_SUBNET"

# Our LAN subnet prefix limited to a 64-bit prefix
LAN_SUBNET_64=$(sipcalc $LAN_IP_SANS_MASK'/64' | fgrep 'Subnet prefix' | cut -d '-' -f 2 | tr -d ' ')
echo '(IPv6)     LAN_SUBNET_64: '\'$LAN_SUBNET_64\'
logger "$(basename "$0")(IPv6): Internet subnet prefix limited to 64 bits: $LAN_SUBNET_64"

# Our LAN subnet prefix sans mask
LAN_SUBNET_NO_MASK=$(/sbin/ip -6 route list dev enp4s0 | egrep -v "fe80" | awk '{print $1}' | awk -F '/' '{print $1}')
echo '(IPv6)LAN_SUBNET_NO_MASK: '\'$LAN_SUBNET_NO_MASK\'
logger "$(basename "$0")(IPv6): Internet subnet prefix sans mask: $LAN_SUBNET_NO_MASK"

# Our LAN address ID
LAN_ADDRESS_ID=$(sipcalc $LAN_IP | fgrep 'Address ID' | cut -d '-' -f 2 | tr -d ' ')
echo '(IPv6)    LAN_ADDRESS_ID: '\'$LAN_ADDRESS_ID\'
logger "$(basename "$0")(IPv6): Internet address ID: $LAN_ADDRESS_ID"

# Example internal machine assignment
CRAIG="${LAN_SUBNET_NO_MASK}512"
echo '(IPv6)             CRAIG: '\'$CRAIG\'


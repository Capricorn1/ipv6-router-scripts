#!/bin/bash

# This script assumes that a prefix delegation (IA-PD) with a /56 prefix length 
# has taken place prior to this script being called or will take place shortly 
# thereafter. With Ubuntu 24.04.01 (and probably Debian) at the very least, the
# current PD assigned to our router can be found using the command:
# ip -6 route | fgrep unreachable | awk '{ print $2 }'
# Grepping for "dhcp" would likely give the same result, but it's not clear if 
# those characters might show up on another route record. 

# The device ID of the WAN Ethernet interface
WAN_IF="enp2s0"

# The device ID of the LAN Ethernet interface
LAN_IF="enp4s0"

# The LAN subnet offset from the WAN subnet in the range "1"-"ff".This script 
# is written expecting a string hexidecimal value added to the first subnet. 
# The first  available subnet would be used as the WAN subnet. For example if 
# the delegated prefix is aaaa:bbbb:cccc:dd00::0/56, then 
# aaaa:bbbb:cccc:dd00::0/64 is the first /64 subnet. The LAN subnet(s) can be
# from aaaa:bbbb:cccc:dd01::0/64 to aaaa:bbbb:cccc:ddff::0/64.
LAN_SUBNET="1"

# The subnet prefix 
EXPECTED_PREFIX_LENGTH="56"

#
# Begin setting the WAN and LAN IPv6 addresses based on the assigned prefix
# delegation.
#
echo "--------------------------------------------------"

HEX_PREFIX_STRING="0x"
PREFIX_DELEGATION_RETRY_COUNT=0	# Current count of attempts to fetch the delegated prefix
PREFIX_DELEGATION_MAX_RETRY=10	# Maximum number of attempts to fetch the delagated prefix
PREFIX_DELEGATION_SLEEP_TIME=10	# Number of seconds to sleep between attempts

PREFIX_DELEGATION_WITH_MASK=""

getDelegatedPrefix() {
	PREFIX_DELEGATION_WITH_MASK=`ip -6 route | fgrep unreachable | awk '{ print $2 }'`
	PREFIX_DELEGATION_RETRY_COUNT=$((PREFIX_DELEGATION_RETRY_COUNT+1))
}

# Check the LAN subnet setting and exit if not in the valid range
LAN_SUBNET_AS_HEX_STRING=$HEX_PREFIX_STRING$LAN_SUBNET
# echo "LAN_SUBNET_AS_HEX_STRING: $LAN_SUBNET_AS_HEX_STRING"
LAN_SUBNET_AS_DEC_NUMBER=$(( ${LAN_SUBNET_AS_HEX_STRING} + 0 ))
# echo "LAN_SUBNET_AS_DEC_NUMBER: $LAN_SUBNET_AS_DEC_NUMBER"

if [ $LAN_SUBNET_AS_DEC_NUMBER -ge 1 -a $LAN_SUBNET_AS_DEC_NUMBER -le 255 ]; then
	echo "LAN SUBNET, $LAN_SUBNET_AS_HEX_STRING, is valid."
else
	echo "LAN SUBNET, $LAN_SUBNET_AS_HEX_STRING, is outside the range of 01 - ff."
	echo "This script will now exit"
	exit 1
fi

getDelegatedPrefix

while [ -z "$PREFIX_DELEGATION_WITH_MASK" -a $PREFIX_DELEGATION_RETRY_COUNT -lt $PREFIX_DELEGATION_MAX_RETRY ];do
	echo "Delegated Prefix not yet known. Sleeping for $PREFIX_DELEGATION_SLEEP_TIME seconds."
	sleep $PREFIX_DELEGATION_SLEEP_TIME
	getDelegatedPrefix
done

if [ -z "$PREFIX_DELEGATION_WITH_MASK" ]; then
	echo "Delegated Prefix was not resolved after $PREFIX_DELEGATION_MAX_RETRY retries."
	echo "This script will now exit"
	exit 1
fi

echo "Assigned prefix delegation with mask is: $PREFIX_DELEGATION_WITH_MASK"

PREFIX_LENGTH=`awk -F "/" '{ print $2 }' <<< $PREFIX_DELEGATION_WITH_MASK`
DELGATED_PREFIX_SANS_MASK=`awk -F "/" '{ print $1 }' <<< $PREFIX_DELEGATION_WITH_MASK`

echo "             Prefix length: $PREFIX_LENGTH"
echo "Delegated prefix sans mask: $DELGATED_PREFIX_SANS_MASK"

if [ $EXPECTED_PREFIX_LENGTH != $PREFIX_LENGTH ]; then
	echo "The computed prefix length, $PREFIX_LENGTH, does not match the expected value, $EXPECTED_PREFIX_LENGTH"
	echo "This script will now exit"
	exit 1
else
	echo "The computed prefix length, $PREFIX_LENGTH, is the expected value."
fi

# The WAN IP is the first /64 subnet out of the /56. Computing it is easy.
# Just slap a 1/64 on the end of the DELGATED_PREFIX_SANS_MASK value.
EXPECTED_WAN_IP="${DELGATED_PREFIX_SANS_MASK}1/64"
echo "      Expected external IP: $EXPECTED_WAN_IP"

CURRENT_WAN_IP=$(/sbin/ip -o -6 addr list $WAN_IF | egrep -v fe80 | awk '{print $4}')

if [ -n "$CURRENT_WAN_IP" ]; then
	echo "Current external IP: $CURRENT_WAN_IP"
	if [ $CURRENT_WAN_IP = $EXPECTED_WAN_IP ];then
		echo "The current WAN IP setting, $CURRENT_WAN_IP, matches the currently expected WAN IP. No changes made."
    else
		echo "The current WAN IP setting, $CURRENT_WAN_IP, does not match the expected WAN IP, $EXPECTED_WAN_IP."
		echo "Removing the WAN IP, $CURRENT_WAN_IP, and setting $EXPECTED_WAN_IP." 
		$( /sbin/ip -6 address del ${CURRENT_WAN_IP} dev ${WAN_IF} ) 
		$( /sbin/ip -6 address add ${EXPECTED_WAN_IP} dev ${WAN_IF} ) 
	fi
else
	echo "No WAN IP was set. Setting it to $EXPECTED_WAN_IP."
	$( /sbin/ip -6 address add ${EXPECTED_WAN_IP} dev ${WAN_IF} ) 
fi    


# The LAN IP can be any of the other 254 available /64 subnets. We need to 
# compute that address by adding the LAN_SUBNET to the numerical value of the 
# 4th hextet. Keep in mind, we need to do hexidecimal math.
FOURTH_HEXTET=`awk -F ":" '{ print $4 }' <<< $DELGATED_PREFIX_SANS_MASK`
# echo "Fourth Hextet: $FOURTH_HEXTET"

FOURTH_HEXTET_AS_HEX_STRING=$HEX_PREFIX_STRING$FOURTH_HEXTET
# echo "FOURTH_HEXTET_IN_HEX: $FOURTH_HEXTET_AS_HEX_STRING"

LAN_SUBNET_AS_NUMBER=$(( ${FOURTH_HEXTET_AS_HEX_STRING} + ${LAN_SUBNET_AS_HEX_STRING} ))
# echo "LAN_SUBNET_AS_NUMBER: $LAN_SUBNET_AS_NUMBER"

LAN_SUBNET_AS_HEX_STRING=`printf '%x\n' ${LAN_SUBNET_AS_NUMBER}`
# echo "LAN_SUBNET_AS_HEX_STRING: $LAN_SUBNET_AS_HEX_STRING"

RESASSEMBLED_LAN_IP=`awk -F ":" '{ print $1 ":" $2 ":" $3 ":" }' <<< $DELGATED_PREFIX_SANS_MASK`
# echo "RESASSEMBLED_LAN_IP: $RESASSEMBLED_LAN_IP"

EXPECTED_LAN_IP=${RESASSEMBLED_LAN_IP}${LAN_SUBNET_AS_HEX_STRING}"::1/64"
echo "Expected LAN IP: $EXPECTED_LAN_IP"

CURRENT_LAN_IP=$(/sbin/ip -o -6 addr list $LAN_IF | egrep -v fe80 | awk '{print $4}')

if [ -n "$CURRENT_LAN_IP" ]; then
    echo "Current LAN IP: $CURRENT_LAN_IP"
    if [ $CURRENT_LAN_IP = $EXPECTED_LAN_IP ];then
        echo "The current LAN IP setting, $CURRENT_LAN_IP, matches the currently expected LAN IP. No changes made."
    else
        echo "The current LAN IP setting, $CURRENT_LAN_IP, does not match the expected LAN IP, $EXPECTED_LAN_IP."
        echo "Removing the LAN IP, $CURRENT_LAN_IP, and setting $EXPECTED_LAN_IP."
        $( /sbin/ip -6 address del ${CURRENT_LAN_IP} dev ${LAN_IF} )
        $( /sbin/ip -6 address add ${EXPECTED_LAN_IP} dev ${LAN_IF} )
    fi
else
    echo "No LAN IP was set. Setting it to $EXPECTED_LAN_IP."
    $( /sbin/ip -6 address add ${EXPECTED_LAN_IP} dev ${LAN_IF} )
fi


exit 0

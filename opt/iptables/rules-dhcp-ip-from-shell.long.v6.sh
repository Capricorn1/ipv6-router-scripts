#!/bin/bash

#
# This script relies on the sipcalc package for some IP calculations. See
# man sipcalc for more info and use apt install sipcalc to install the 
# package.
#

# Set the following to "0" to turn on default logging or to "1" to run silently.
RUN_SILENTLY="0"

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Starting IPv6 firewalling... "
fi

######################################################################
######################################################################
# Some definitions for easy maintenance.                             #
######################################################################
######################################################################
#
######################################################################
# Set the following to "1" if this firewall is operating within a
# internal non-routable firewall. Generally, this only occurs when
# setting up a new firewall.
######################################################################

INTERNAL_FIREWALL="0"

if [ "$INTERNAL_FIREWALL" == "1" ]; then
        echo "This in an internal firewall ... "
fi

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Setting IPv6 definitions... "
fi
IP6TABLES=/sbin/ip6tables

######################################################################
# Firewall Operation Definitions
######################################################################
# Set to 1 if connection tracking is supported
USE_CONNECTION_TRACKING="1"

# Allow external clients to use Auth facility = "1"; "0" otherwise
ACCEPT_EXTERNAL_AUTH="0"

# This firewall is a DHCP client on the WAN (i.e., uses a dynamically assigned IP address
ISA_DHCP6_CLIENT="1"

# This firewall is a DHCP server for the LAN (e.g., is a DHCP server to an internal network)
ISA_DHCP6_SERVER="1"


######################################################################
# Load modules
######################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	logger "$(basename "$0")(IPv6): Starting to load ip6tables rules."
	echo -n "(IPv6)Loading modules: "
fi
# Load modules
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ip6_tables, "
fi
modprobe ip6_tables

if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ip6table_filter, "
fi
modprobe ip6table_filter

if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    if [ "$RUN_SILENTLY" != "1" ]; then
         echo -n ", nf_conntrack, "
    fi
    modprobe nf_conntrack       # Gives iptables ability to track connections

    if [ "$RUN_SILENTLY" != "1" ]; then
         echo -n "nf_conntrack_ftp, "
    fi
    modprobe nf_conntrack_ftp   # Gives iptables ability to track outbound FTP connections
fi

if [ "$RUN_SILENTLY" != "1" ]; then
	echo ""
	logger "$(basename "$0")(IPv6): Connection tracking and NAT modules loaded (if enabled)"
fi
                                                                                
######################################################################
# Reserved private (internal-non routable) IP Addresses
######################################################################
LOOPBACK="::1"                      # reserved loopback address 
LINK_LOCAL="fe80::/10"              # reserved link local address range
SITE_LOCAL="fec0::/10"              # reserved site local address range
UNIQUE_LOCAL_ADDRESS="fd00::/8"     # Unique Local Address range
MULTICAST="ff00::/8"                # IPv6 Multicast address range

######################################################################
# Special Network IP Addresses and Ports
######################################################################
PRIVPORTS="0:1023"                  # wellknown, privileged port range
UNPRIVPORTS="1024:65535"            # unprivileged port range
ANYWHERE="::"                       # match any IP address

## Example IP breakdown
## 2600:4040:4026:0300:0000:0000:0000:0000/56 
## XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX
## |||| |||| |||| |||| |||| |||| |||| ||||
## |||| |||| |||| |||| |||| |||| |||| |||128
## |||| |||| |||| |||| |||| |||| |||| ||124
## |||| |||| |||| |||| |||| |||| |||| |120
## |||| |||| |||| |||| |||| |||| |||| 116
## |||| |||| |||| |||| |||| |||| |||112
## |||| |||| |||| |||| |||| |||| ||108
## |||| |||| |||| |||| |||| |||| |104
## |||| |||| |||| |||| |||| |||| 100
## |||| |||| |||| |||| |||| |||96
## |||| |||| |||| |||| |||| ||92
## |||| |||| |||| |||| |||| |88
## |||| |||| |||| |||| |||| 84
## |||| |||| |||| |||| |||80
## |||| |||| |||| |||| ||76
## |||| |||| |||| |||| |72
## |||| |||| |||| |||| 68
## |||| |||| |||| |||64
## |||| |||| |||| ||60
## |||| |||| |||| |56
## |||| |||| |||| 52
## |||| |||| |||48
## |||| |||| ||44
## |||| |||| |40
## |||| |||| 36
## |||| |||32
## |||| ||28
## |||| |24
## |||| 20
## |||16
## ||8
## |4
## 0

## There are 256 subnets in the /64 range including:
## 2600:4040:4026:0300:0000:0000:0000:0000/64
## 2600:4040:4026:0301:0000:0000:0000:0000/64
## 2600:4040:4026:0302:0000:0000:0000:0000/64
## . . .
## 2600:4040:4026:03fd:0000:0000:0000:0000/64
## 2600:4040:4026:03fe:0000:0000:0000:0000/64
## 2600:4040:4026:03ff:0000:0000:0000:0000/64


######################################################################
# Unlike IPv4 operations, DHCP and other broadcasts needed for 
# initialization are done on the Link Local subnet before the global, 
# public IPv6 address is known. Therefore the link local initization,
# firewall chains, and firewall rules need to be in place before the
# public IP initialization, chains, and firewall rules are ready to
# be added. Therefore, firewall initialization in IPv6 is a two-stage
# process.
######################################################################


######################################################################
######################################################################
# Interface definitions
######################################################################
######################################################################


######################################################################
# Loopback
######################################################################
LOOPBACK_IF="lo"                        # Local loopback interface


######################################################################
# WAN side definitions 
######################################################################
INTERNET_IF="enp2s0"                   	# WAN (Internet) interface (NIC) device name
echo '(IPv6)            INTERNET_IF: '\'$INTERNET_IF\'
logger "$(basename "$0")(IPv6): Internet inteface: $INTERNET_IF"


######################################################################
# LAN side definitions
######################################################################
LAN_IF="enp4s0" 			# internal LAN interface (NIC) device name
echo '(IPv6)                 LAN_IF: '\'$LAN_IF\'
logger "$(basename "$0")(IPv6): LAN inteface: $LAN_IF"


######################################################################
# Link Local Subnet on external interface (dynamically created)
######################################################################
EXT_LINKLOCAL_IP=""
LINK_LCL_ADDR_RETRY_COUNT=0		# Current Link Local Address resolution retry count
LINK_LCL_ADDR_RETRY_MAX=20		# Maximum number of times to retry before giving up
LINK_LCL_ADDR_RETRY_SLEEP_TIME=10 	# Seconds to sleep between retrys

getIpv6ExternalLinkLocalAddress() {
	EXT_LINKLOCAL_IP=$(/sbin/ip -o -6 addr list $INTERNET_IF | egrep fe80 | awk '{print $4}')
	LINK_LCL_ADDR_RETRY_COUNT=$((LINK_LCL_ADDR_RETRY_COUNT+1))
}

getIpv6ExternalLinkLocalAddress
while [ -z "$EXT_LINKLOCAL_IP" -a $LINK_LCL_ADDR_RETRY_COUNT -le $LINK_LCL_ADDR_RETRY_MAX ]; do
    	echo "(IPv6)External IPv6 link local IP address not yet known. Sleeping for $IP_ADDR_RETRY_SLEEP_TIME seconds."
	sleep $IP_ADDR_RETRY_SLEEP_TIME	
	getIpv6ExternalLinkLocalAddress
done

if [ -z "$EXT_LINKLOCAL_IP" ]; then
    echo "(IPv6)External IPv6 link local IP address not resolved. Exiting."
    logger "$(basename "$0")(IPv6): External IPv6 link local IPv6 IP address not resolved. Exiting."
    exit 1
fi

echo '(IPv6)       EXT_LINKLOCAL_IP: '\'$EXT_LINKLOCAL_IP\'
logger "$(basename "$0")(IPv6): Ext Link local subnet: $EXT_LINKLOCAL_IP"

EXT_LINKLOCAL_SUBNET=$(sipcalc $EXT_LINKLOCAL_IP | fgrep 'Subnet prefix' | cut -d '-' -f 2 | tr -d ' ')
echo '(IPv6)   EXT_LINKLOCAL_SUBNET: '\'$EXT_LINKLOCAL_SUBNET\'
logger "$(basename "$0")(IPv6): Ext Link local SUBNET: $EXT_LINKLOCAL_SUBNET"

EXT_INTERNET_GATEWAY=$EXT_LINKLOCAL_IP
echo '(IPv6)   EXT_INTERNET_GATEWAY: '\'$EXT_INTERNET_GATEWAY\'
logger "$(basename "$0")(IPv6): Ext Gateway IP: $EXT_INTERNET_GATEWAY"


######################################################################
# LAN side link local definitions on the internal interface 
######################################################################
INT_LINKLOCAL_IP=$(/sbin/ip -o -6 addr list $LAN_IF | egrep fe80 | awk '{print $4}')
if [ -z "$INT_LINKLOCAL_IP" ]; then
    echo "(IPv6)Internal link local IPv6 IP address not yet known. Exiting."
    logger "$(basename "$0")(IPv6): Internal link local IPv6 IP address not yet known. Exiting."
    exit 0
fi
echo '(IPv6)       INT_LINKLOCAL_IP: '\'$INT_LINKLOCAL_IP\'
logger "$(basename "$0")(IPv6): Int Link local ip: $INT_LINKLOCAL_IP"

INT_LINKLOCAL_SUBNET=$(sipcalc $INT_LINKLOCAL_IP | fgrep 'Subnet prefix' | cut -d '-' -f 2 | tr -d ' ')
echo '(IPv6)   INT_LINKLOCAL_SUBNET: '\'$INT_LINKLOCAL_SUBNET\'
logger "$(basename "$0")(IPv6): Int Link local subnet: $INT_LINKLOCAL_SUBNET"

INT_LINKLOCAL_GATEWAY=$INT_LINKLOCAL_IP
echo '(IPv6)  INT_LINKLOCAL_GATEWAY: '\'$INT_LINKLOCAL_GATEWAY\'
logger "$(basename "$0")(IPv6): Int Link Local Gateway IP: $INT_LINKLOCAL_GATEWAY"


######################################################################
# At this point, we have the external and internal link local IP 
# addresses. Create the chains and then add the rules that work
# solely on the link local (and multicast) interfaces. 
######################################################################


######################################################################
# Definition of user chains:
######################################################################
#  Remember: the firewall is the center of our universe as far as firewall rules
#  are concerned. Every rule and chain is taken from the point of view of the
#  firewall. That is why lan_if_in refers to traffic coming in from the LAN
#  rather than traffic coming in from the Internet.
#
#  ext_if_in:
#	Packets destined to our external IP address from an addresses on
#	the Internet
#  ext_if_out:
#	Packets generated from our external IP address destined to addresses on
#	the Internet
#  ext_if_llcl_multi_in:
#	Packets destined to our external multicast IP address from link local 
#       addresses on the Internet
#  ext_if_llcl_multi_out:
#	Packets generated from our link local IP address on the external interface
#       destined to multicast addresses on the Internet
#  ext_if_llcl_multi_icmp_in:
#	ICMP packets destined to our external multicast IP address from link local 
#       addresses on the Internet
#  ext_if_llcl_multi_icmp_out:
#	ICMP packets generated from our link local IP address on the external interface
#       destined to multicast addresses on the Internet
#  ext_if_icmp_out:
#	ICMP requests made from our firewall machine to a destination on the Internet
#  ext_if_icmp_in:
#	ICMP requests made from sources on the Internet and destined to 
#	external interface (the firewall machine itself)
#  dropped_log_in:
#	The chain used to log traffic at the external interface from the Internet
#  ext_if_log_out:
#	The chain used to log traffic leaving the external interface to the Internet
#  int_ext:
#	Packets on the forwarding chain generated by our internal LAN and destined
#	to the Internet
#  ext_int:
#	Packets on the forwarding chain coming from the Internet and destined to
#	one of the machines on our internal LAN
#  int_ext_icmp:
#	ICMP packets on the forwarding chain from our LAN machines to
#	the destinations on the Internet. (ICMP requests only)
#  ext_int_icmp:
#	ICMP packets on the forwarding chain from the Internet destined to machines
#	on our LAN (responses to our ICMP requests only)
#  lan_if_in:
#	Packets generated from our LAN IP address range destined to addresses on
#	the Internet and are to be routed through the firewall and therefore are
#	coming "in" from our LAN
#  lan_if_out:
#	Packets that have been routed through or generated by the firewall machine
#       that are destined to machines on the internal LAN. Therefore, these will be 
#	sent "out" to our LAN
#  lan_if_llcl_multi_in:
#	Packets generated from machines on the LAN using a link local IP address 
#       and that are destined a multicast address on the firewall and therefore are 
#       coming "in" from our LAN
#  lan_if_llcl_multi_out:
#	Packets generated by the firewall with link local IP addresses that are destined 
#       to the multicast addresses on the internal LAN. Therefore, these will be 
#	sent "out" to our LAN
#  lan_if_subnet_llcl_in:
#	Packets generated from machines on the LAN using a permanent or temporary address
#       for our LAN's subnet and directed to the link local IP address of the firewall
#  lan_if_llcl_subnet_out:
#	Packets generated by the firewall from its link local IP addresses that are destined 
#       to device on our LAN that has a permanent or temporary IP address on our LAN's subnet
#  lan_if_subnet_multi_in:
#	Packets generated from machines on the LAN using a permanent or temporary address
#       for our LAN's subnet and directed to the multicast IP range
#  lan_if_fwl_multi_out:
#	Packets generated by the firewall from its permanent or temporary IP addresses that 
#       are destined to the multicast IP range
#  lan_if_subnet_multi_icmp_in:
#	ICMP packets generated from machines on the LAN using a permanent or temporary address
#       for our LAN's subnet and directed to the multicast IP range
#  lan_if_fwl_multi_icmp_out:
#	ICMP packets generated by the firewall from its permanent or temporary IP addresses that 
#       are destined to the multicast IP range
#  lan_if_llcl_multi_icmp_in:
#	ICMP packets generated from machines on the LAN using a link local IP address 
#       and that are destined a multicast address on the firewall and therefore are 
#       coming "in" from our LAN
#  lan_if_llcl_multi_icmp_out:
#	ICMP packets generated by the firewall with link local IP addresses that are destined 
#       to the multicast addresses on the internal LAN. Therefore, these will be 
#	sent "out" to our LAN
#  lan_if_subnet_llcl_icmp_in:
#	ICMP Packets generated from machines on the LAN using a permanent or temporary address
#       for our LAN's subnet and directed to the link local IP address of the firewall
#  lan_if_llcl_subnet_icmp_out:
#	ICMP Packets generated by the firewall from its link local IP addresses that are destined 
#       to device on our LAN that has a permanent or temporary IP address on our LAN's subnet
#  lan_if_icmp_in:
#	ICMP packets generated by internal LAN machines toward the internal LAN
#	interface or the external WAN interface on the firewall
#  lan_if_icmp_out:
#	ICMP packets generated by the LAN or WAN interfaces on the firewall destined to
#	the internal LAN machines (primary for responses and pinging LAN machines)
#  LAN_udp_firewall_request:
#	UDP packets generated by the firewall machine specifically aimed at one of the 
#	internal lan machines
#  LAN_udp_firewall_response:
#	UDP packets generated from the internal lan machines as responses to requests
#	by the firewall machine
#  LAN_tcp_firewall_request:
#	TCP packets generated by the firewall machine specifically aimed at one of the 
#	internal lan machines
#  LAN_tcp_firewall_response:
#	TCP packets generated from the internal lan machines as responses to requests
#	by the firewall machine
#  ext_if_lan_in:
#	Packets generated from the LAN that are destined to the firewall's external
#	IP address on the forward chain
#  ext_if_lan_out:
#	Packets destined to the LAN that are generated by the firewall's external
#	IP address on the forward chain (in response to packets generated by the 
#	LAN to this interface).
#  tcp_state_flags:
#	Special chain used to log and drop packets with illegal TCP state combinations
#  connection_tracking:
#	Special chain used to detect Established & Related traffic to short-circuit
#	further testing. (Established & Related traffic is quickly accepted.)
#  source_address_check:
#	Special chain used to check the validity of the source address of packets
#	coming from the internet (usually)
#  destination_address_check:
#	Special chain used to check the validity of the destination address of packets
#	coming from the internet (usually) (typically watching for spoofed broadcast 
#	packets)
#  lcl_dns_srv_to_trust_dns_srv:
#	Used to check our local DNS server making queries to the primary DNS
#	servers of our ISP and/or our trusted slave servers and those servers
#	making requests of our DNS server for the domains we are the master of
#  lcl_dns_srv_fm_trust_dns_srv:
#	Used to check our local DNS server getting responses from the primary DNS
#	servers of our ISP and/or our trusted slave servers and those servers
#	making requests of our DNS server for the domains we are the master of
#  trusted_dns_srv_LAN_query:
#	Chain used to check the validity of requests made to our local DNS servers
#	from machines within our LAN
#  lcl_dns_srv_rmt_query:
#	Chain used to check the validity of requests made to our local DNS servers
#	from the Internet
#  trusted_dns_srv_LAN_response:
#	Used to check the response of local DNS server going to our local LAN
#  lcl_dns_srv_rmt_response:
#	Used to check the response of local DNS server going to requestors on the
#	Internet
#  rmt_dns_srv_query:
#	Chain used to check the validity of requests made to remote (trusted) DNS 
#	servers from the internal LAN and external IP (normal requests)
#  rmt_dns_srv_response:
#	Used to check the validity of reponses coming from a remote DNS server to
#	our internal LAN  and external IP (normal requests)
#  lcl_tcp_client_request:
#	A request from our external interface (firewall) or our LAN machines to a 
#	remote TCP-based server on the Internet
#  rmt_tcp_srv_response:
#	A response from a remote TCP-based server on the Internet to our firewall
#	or LAN machines (in response to a request)
#  rmt_tcp_client_request:
#	A request from a client on the Internet to a TCP-based service on our firewall
#  lcl_tcp_srv_response:
#	A response from our firewall TCP-based server to a client on the Internet
#  LAN_tcp_client_request:
#	Internal LAN TCP clients requests to services that appear on the firewall 
#	machine (whether that's where they truly are or not)
#  tcp_srv_LAN_response:
#	Repsonses from the firewall TCP-based services back to clients on our internal
#	LAN
#  local_udp_client_request:
#	A request from our external interface (firewall) or our LAN machines to a 
#	remote UDP-based server on the Internet
#  remote_udp_srv_response:
#	A response from a remote UDP-based server on the Internet to our firewall
#	or LAN machines (in response to a request)
#  lcl_dhcp_client_query:
#	A local DHCP client on the firewall making a DHCP query to the ISP
#  rmt_dhcp_srv_response:
#	Our ISP's response to the client query from our local DHCP Client
#  local_dhcp_server_query:
#  	Our Firewall's DHCP Server getting a request from a device on our LAN.
#  local_dhcp_srv_response:
#  	Our Firewall's DHCP Server response to a request from a device on our LAN.
#  log_tcp_state:
#  	Log (usually invalid) TCP states
#

USER_CHAINS="ext_if_in                  	ext_if_out \
        ext_if_llcl_multi_in			ext_if_llcl_multi_out \
        ext_if_llcl_multi_icmp_in		ext_if_llcl_multi_icmp_out \
        ext_if_llcl_llcl_in			ext_if_llcl_llcl_out \
        ext_if_llcl_llcl_icmp_in		ext_if_llcl_llcl_icmp_out \
	ext_if_icmp_in             		ext_if_icmp_out \
	dropped_log_in             		dropped_log_out \
     	int_ext					ext_int \
     	int_ext_icmp				ext_int_icmp \
        lan_if_in				lan_if_out \
       	lan_if_llcl_multi_in			lan_if_llcl_multi_out \
       	lan_if_llcl_multi_icmp_in		lan_if_llcl_multi_icmp_out \
     	lan_if_subnet_llcl_in			lan_if_llcl_subnet_out \
     	lan_if_subnet_llcl_icmp_in		lan_if_llcl_subnet_icmp_out \
 	lan_if_subnet_multi_in     		lan_if_fwl_multi_out \
       	lan_if_subnet_multi_icmp_in 		lan_if_fwl_multi_icmp_out \
       	lan_if_llcl_llcl_in			lan_if_llcl_llcl_out \
       	lan_if_llcl_llcl_icmp_in		lan_if_llcl_llcl_icmp_out \
       	lan_if_icmp_in             		lan_if_icmp_out \
     	LAN_udp_firewall_request		LAN_udp_firewall_response \
     	LAN_tcp_firewall_request		LAN_tcp_firewall_response \
     	ext_if_lan_out				ext_if_lan_in \
       	tcp_state_flags            		connection_tracking  \
       	source_address_check       		destination_address_check  \
     	lcl_dns_srv_to_trust_dns_srv 		lcl_dns_srv_fm_trust_dns_srv \
     	trusted_dns_srv_LAN_query  		lcl_dns_srv_rmt_query \
     	trusted_dns_srv_LAN_response		lcl_dns_srv_rmt_response \
       	rmt_dns_srv_query			rmt_dns_srv_response  \
       	lcl_tcp_client_request			rmt_tcp_srv_response \
       	local_udp_client_request		remote_udp_srv_response \
       	remote_udp_client_request		local_udp_srv_response \
       	rmt_tcp_client_request			lcl_tcp_srv_response \
     	LAN_tcp_client_request			tcp_srv_LAN_response \
     	LAN_udp_client_request			udp_srv_LAN_response \
	lcl_dhcp_client_query			rmt_dhcp_srv_response \
       	LAN_dhcp_client_query			LAN_dhcp_srv_response \
     	steamdeck_in				steamdeck_out \
     	vpn_machine_in				vpn_machine_out \
     	laptop_in				laptop_out \
	network_printer_in			network_printer_out \
     	file_server_in				file_server_out \
     	gaming_pc_in				gaming_pc_out \
     	guest_gamer_in				guest_gamer_out \
     	wap_in					wap_out \
     	smartplugswitch_in			smartplugswitch_out \
     	samsungphone_in				samsungphone_out \
     	galaxytablet_in				galaxytablet_out \
     	oculusquest2_in				oculusquest2_out \
     	roku_in					roku_out \
     	ecobee3_in				ecobee3_out \
     	switch_in				switch_out \
     	wirelessplug_in				wirelessplug_out \
     	log_in					log_out \
       	log_tcp_state				log_forward"


#########################################################################################
#########################################################################################
# Server IP addresses and definitions for DHCP and DNS over Link Local subnet
#########################################################################################
#########################################################################################


#########################################################################################
# DHCP over link local subnet
#########################################################################################
LOCAL_DHCP_SERVER_LINK_LOCAL=$INT_LINKLOCAL_IP  # The interface for SOLICIT requests from
#                                               # DHCPv6 clients inside the firewall
REMOTE_DHCP_SERVER_LINK_LOCAL=$EXT_INTERNET_GATEWAY	# External DHCP server
DHCP_IPV6_SOLICIT_UDP_PRT=546					# IPv6 Solicit from a Link Local IP:UDP:546 to ...
DHCP_IPV6_ADVERTISE_UDP_PORT=547				# Mulitcast:UDP:547 as part of DHCP negotiation
# Example
# In this example, without rapid-commit present, the server's link-local address is 
# fe80::0011:22ff:fe33:5566 and the client's link-local address is fe80::aabb:ccff:fedd:eeff.
#
# - Client sends a solicit from [fe80::aabb:ccff:fedd:eeff]:546 to multicast address [ff02::1:2]:547.
# - Server replies with an advertise from [fe80::0011:22ff:fe33:5566]:547 to [fe80::aabb:ccff:fedd:eeff]:546.
# - Client replies with a request from [fe80::aabb:ccff:fedd:eeff]:546 to [ff02::1:2]:547.
# - Server finishes with a reply from [fe80::0011:22ff:fe33:5566]:547 to [fe80::aabb:ccff:fedd:eeff]:546.


#########################################################################################
# DNS over link local subnet
#########################################################################################
NAMESERVER_1="2001:4860:4860:0:0:0:0:8888"  	# Google's Open DNS server (primary)
NAMESERVER_2="2001:4860:4860:0:0:0:0:8844"  	# Google's Open DNS server (secondary)
# NAMESERVER_3="2001:558:feed::1"             	# Xfinity Nameserver primary
# NAMESERVER_4="2001:558:feed::2"             	# Xfinity Nameserver secondary
NAMESERVER_3="2606:4700:4700::1111"				# Cloudflare Nameserver primary
NAMESERVER_4="2606:4700:4700::1001"    			# Cloudflare Nameserver secondary
MULTICAST_DNS_UDP_PORT="5353"					# Multicast DNS (MDNS)


######################################################################
######################################################################
# Initial Firewall Rules - Essentially drop most traffic
######################################################################
######################################################################
# Stop all traffic while we set the rules
if [ "$RUN_SILENTLY" != "1" ]; then
    echo "(IPv6)Applying ip6tables firewall rules: ..."
    echo "(IPv6)Stopping all traffic except on loopback interface while the "
    echo "(IPv6) rules are being reset..."
    logger "$(basename "$0")(IPv6): Applying ip6tables firewall rules: ..."
    # ##not v6## logger "$(basename "$0")(IPv6): Stopping all traffic except on loopback interface while the rules are being reset..." 
fi

# Flush any existing rules from all chains
if [ "$RUN_SILENTLY" != "1" ]; then
    echo "(IPv6)Flushing all previous rules: ... "
    logger "$(basename "$0")(IPv6): Flushing all previous rules: ..."
fi
$IP6TABLES -F

$IP6TABLES -I INPUT 1 ! -i $LOOPBACK_IF -j DROP
$IP6TABLES -I FORWARD 1 -j DROP

# Remove any pre-existing user-defined chains
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Deleting user-defined chains: ..."
    	logger "$(basename "$0")(IPv6): Deleting user-defined chains: ..."
fi
$IP6TABLES --delete-chain

# Unlimited traffic on the LOOPBACK interface
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Enabling unlimited internal traffic on the loopback interface ..."
    	logger "$(basename "$0")(IPv6): Enabling unlimited internal traffic on the loopback interface ..."
fi
$IP6TABLES -A INPUT  -i $LOOPBACK_IF -j ACCEPT
$IP6TABLES -A OUTPUT -o $LOOPBACK_IF -j ACCEPT

# Unlimited UDP DHCP REQUEST/RESPONSE on the LAN Interface
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Enabling unlimited UDP DHCP requests and responses on the LAN interface ..."
    	logger "$(basename "$0")(IPv6): Enabling unlimited UDP DHCP requests and responses on the LAN interface ..."
fi
$IP6TABLES -A INPUT  -i $LAN_IF -p udp --sport $DHCP_IPV6_SOLICIT_UDP_PRT --dport $DHCP_IPV6_ADVERTISE_UDP_PORT -j ACCEPT
$IP6TABLES -A OUTPUT -o $LAN_IF -p udp --sport $DHCP_IPV6_ADVERTISE_UDP_PORT --dport $DHCP_IPV6_SOLICIT_UDP_PRT -j ACCEPT

# Set the default policy to drop, however we often drop or reject 
# within the chains we're about to define as well.
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Setting default policy to DROP"
    	logger "$(basename "$0")(IPv6): Setting default policy to DROP"
fi
$IP6TABLES -t filter --policy INPUT   DROP
$IP6TABLES -t filter --policy OUTPUT  DROP
$IP6TABLES -t filter --policy FORWARD DROP


###############################################################
# Create the user-defined chains
###############################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Creating the user-defined chains."
    	logger "$(basename "$0")(IPv6): Creating the user-defined chains."
fi
for i in $USER_CHAINS; do
    $IP6TABLES -N $i
done


######################################################################
######################################################################
# Link Local Firewall Rules - Allow DHCP and DNS traffic
######################################################################
######################################################################

###############################################################
# Netfilter supported protection
###############################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Setting NetFilter supported protections: "
fi

# Disable Source Routed Packets
echo "disable source routed packets, "
for f in /proc/sys/net/ipv6/conf/*/accept_source_route; do
    echo 0 > $f
done

echo " "

###############################################################
# Link Local subnet firewall rules
###############################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Establishing Link Local rules: "
fi

#########################################################################################
# Link Local ICMP requests to and from the firewall machine from the Internet
# Some Link Local requests are to/from a Link Local IP to the Multicast subnet and 
# others are to/from a Link Local IP from/to the Firewall's Link Local IP address 
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)ICMP F/W-WAN (Link Local): "
fi

#####################
# Set up the chains #
#####################
$IP6TABLES -A ext_if_llcl_multi_in -p icmpv6 -j ext_if_llcl_multi_icmp_in 
$IP6TABLES -A ext_if_llcl_multi_out -p icmpv6 -j ext_if_llcl_multi_icmp_out
$IP6TABLES -A ext_if_llcl_llcl_in -p icmpv6 -j ext_if_llcl_llcl_icmp_in 
$IP6TABLES -A ext_if_llcl_llcl_out -p icmpv6 -j ext_if_llcl_llcl_icmp_out

####################
# Set up the rules #
####################
# Unlike in IPv4, IPv6 routers never fragment IPv6 packets. Packets exceeding the size 
# of the maximum transmission unit (MTU) of the destination link are dropped and this 
# condition is signaled by a Packet too big ICMPv6 message to the originating node, 
# similarly to the IPv4 method when the Don't Fragment bit is set.
# Log and drop initial ICMP fragments
# if [ "$RUN_SILENTLY" != "1" ]; then
# 	echo -n "(IPv6)frag drop, "
# fi
# $IP6TABLES -A ext_if_icmp_in --fragment -j LOG --log-prefix "(IPv6)(D)Fragmented incoming ICMP: "
# $IP6TABLES -A ext_if_icmp_in --fragment -j DROP
# $IP6TABLES -A ext_if_icmp_out --fragment -j LOG --log-prefix "(IPv6)(D)Fragmented outgoing ICMP: "
# $IP6TABLES -A ext_if_icmp_out --fragment -j DROP

# Router solicitation (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "router solicitation (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type router-solicitation \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT

# Router advertising (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "router advertisement (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type router-advertisement \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT

# Router solicitation (outigoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "router solicitation (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type router-solicitation \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT

# Router advertisement (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) router advertisement (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type router-advertisement \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT

# Multicast listener query (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "multicast listener query (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type 130 \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type 130 -j ACCEPT

# Multicast listener query (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "multicast listener query (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type 130 \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type 130 -j ACCEPT

# Multicast listener report (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) multicast listener report (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type 131 \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type 131 -j ACCEPT

# Multicast listener report (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "multicast listener report (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type 131 \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type 131 -j ACCEPT

# Link local to multicast neighbor solicitation (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) link local - multicast neighbor solicitation (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type neighbor-solicitation \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT

# Link local to link local neighbor solicitation (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "link local - link local neighbor solicitation (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_llcl_icmp_in -p icmpv6 --icmpv6-type neighbor-solicitation \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_llcl_icmp_in -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT

# Link local to multicast neighbor solicitation (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) link local - multicast neighbor solicitation (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type neighbor-solicitation \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT

# Link local to link local neighbor solicitation (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "link local - link local neighbor solicitation (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_llcl_icmp_out -p icmpv6 --icmpv6-type neighbor-solicitation \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_llcl_icmp_out -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT

# Multicast Listener Discovery (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) multicast listener discovery (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type 143 \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type 143 -j ACCEPT

# Neighbor advertisement (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "neighbor advertisement (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type neighbor-advertisement \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

# Neighbor advertisement (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "neighbor advertisement (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type neighbor-advertisement \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

# Outgoing ping and incoming reply
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "ping (out), reply (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type echo-request \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type echo-request -j ACCEPT
$IP6TABLES -A ext_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type echo-reply -j ACCEPT

# Incoming ping
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6) ping (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type echo-request \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type echo-request \
	-j ACCEPT
$IP6TABLES -A ext_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type echo-reply \
	-j ACCEPT

echo " "

#########################################################################################
# ICMP requests to and from the internal LAN to both the internal interface and the
# external interface. (We treat requests from the internal machines the same way 
# regardless of which interface they hit.)
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)ICMP F/W-LAN (Link Local): "
fi

#####################
# Set up the chains #
#####################
$IP6TABLES -A lan_if_llcl_multi_in -p icmpv6 -j lan_if_llcl_multi_icmp_in
$IP6TABLES -A lan_if_llcl_multi_out -p icmpv6 -j lan_if_llcl_multi_icmp_out
$IP6TABLES -A lan_if_llcl_llcl_in -p icmpv6 -j lan_if_llcl_llcl_icmp_in
$IP6TABLES -A lan_if_llcl_llcl_out -p icmpv6 -j lan_if_llcl_llcl_icmp_out
$IP6TABLES -A lan_if_subnet_llcl_in -p icmpv6 -j lan_if_subnet_llcl_icmp_in
$IP6TABLES -A lan_if_llcl_subnet_out -p icmpv6 -j lan_if_llcl_subnet_icmp_out
$IP6TABLES -A lan_if_subnet_multi_in -p icmpv6 -j lan_if_subnet_multi_icmp_in
$IP6TABLES -A lan_if_fwl_multi_out -p icmpv6 -j lan_if_fwl_multi_icmp_out

####################
# Set up the rules #
####################
# Link local to multicast router solicitation (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "llcl->multi router solicitation (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type router-solicitation \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT

# Link local to link local router solicitation (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "llcl->llcl router solicitation (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_llcl_icmp_in -p icmpv6 --icmpv6-type router-solicitation \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_llcl_icmp_in -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT

# Link local to multicast router advertisement (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6) llcl->multi router advertisement (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type router-advertisement \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT

# Link local to link local router advertisement (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "llcl->llcl router advertisement (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_llcl_icmp_in -p icmpv6 --icmpv6-type router-advertisement \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_llcl_icmp_in -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT

# Link local to multicast router advertisement (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6) llcl->multi router advertisement (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type router-advertisement \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT

# Link local to link local router advertisement (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "llcl->llcl router advertisement (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_llcl_icmp_out -p icmpv6 --icmpv6-type router-advertisement \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_llcl_icmp_out -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT

# Multicast listener query (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) llcl->multi multicast listener query (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type 130 \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type 130 -j ACCEPT

# Multicast listener query (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "llcl->multi multicast listener query (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type 130 \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type 130 -j ACCEPT

# Multicast listener report (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) llcl->multi multicast listener report (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type 131 \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type 131 -j ACCEPT

# Multicast listener report (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "llcl->multi multicast listener report (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type 131 \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type 131 -j ACCEPT

# Multicast listener done (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) llcl->multi multicast listener done (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type 132 \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type 132 -j ACCEPT

# Multicast listener done (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "llcl->multi multicast listener done (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type 132 \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type 132 -j ACCEPT

# Link local to multicast neighbor solicitation (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) llcl->multi neighbor solicitation (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type neighbor-solicitation \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT

# Link local to multicast neighbor solicitation (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "llcl->multi neighbor solicitation (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type neighbor-solicitation \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT

# Link local to link local neighbor solicitation (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) llcl->llcl neighbor solicitation (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_llcl_icmp_in -p icmpv6 --icmpv6-type neighbor-solicitation \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_llcl_icmp_in -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT

# Link local to link local neighbor solicitation (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "llcl->llcl neighbor solicitation (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_llcl_icmp_out -p icmpv6 --icmpv6-type neighbor-solicitation \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_llcl_icmp_out -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT

# Firewall's link local IP to LAN subnet neighbor advertisement (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) llcl->subnet neighbor advertisement (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_subnet_icmp_out -p icmpv6 --icmpv6-type neighbor-advertisement \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_subnet_icmp_out -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

# Firewall's link local IP to LAN subnet neighbor solicitation (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "llcl->subnet neighbor solicitation (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_subnet_icmp_out -p icmpv6 --icmpv6-type neighbor-solicitation \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_subnet_icmp_out -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT

# Firewall's subnet IP to multicast neighbor advertisement (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) firewall->multicast neighbor advertisement (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_fwl_multi_icmp_out -p icmpv6 --icmpv6-type neighbor-advertisement \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_fwl_multi_icmp_out -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

# Firewall's link local IP to LAN subnet neighbor solicitation (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "firewall->multicast neighbor solicitation (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_fwl_multi_icmp_out -p icmpv6 --icmpv6-type neighbor-solicitation \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_fwl_multi_icmp_out -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT

# Link local to multicast neighbor advetisement (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) llcl->multi neighbor advertisement (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type neighbor-advertisement \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

# Link local to multicast neighbor advertisement (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "llcl->multi neighbor advertisement (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type neighbor-advertisement \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

# Link local to link local neighbor advetisement (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) llcl->llcl neighbor advertisement (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_llcl_icmp_in -p icmpv6 --icmpv6-type neighbor-advertisement \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_llcl_icmp_in -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

# LAN subnet devices to firewall's link local IP neighbor advetisement (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "subnet->llcl IP neighbor advertisement (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_subnet_llcl_icmp_in -p icmpv6 --icmpv6-type neighbor-advertisement \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_subnet_llcl_icmp_in -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

# LAN subnet devices to firewall's link local IP neighbor solicitation (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) subnet->llcl IP neighbor solicitation (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_subnet_llcl_icmp_in -p icmpv6 --icmpv6-type neighbor-solicitation \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_subnet_llcl_icmp_in -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT

# LAN subnet devices to Multicast IP neighbor advetisement (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "subnet->multicast IP neighbor advertisement (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_subnet_multi_icmp_in -p icmpv6 --icmpv6-type neighbor-advertisement \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_subnet_multi_icmp_in -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

# LAN subnet devices to Multicast IP neighbor solicitation (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) subnet->multicast IP neighbor solicitation (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_subnet_multi_icmp_in -p icmpv6 --icmpv6-type neighbor-solicitation \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_subnet_multi_icmp_in -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT

# Link local to link local neighbor advertisement (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "llcl->llcl neighbor advertisement (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_llcl_icmp_out -p icmpv6 --icmpv6-type neighbor-advertisement \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_llcl_icmp_out -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

# Outgoing ping and incoming reply
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6) llcl->multi ping (out), llcl->multi reply (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type echo-request \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type echo-request -j ACCEPT
$IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type echo-reply -j ACCEPT

# Incoming ping
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& llcl->multi ping (in). "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type echo-request \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lan_if_llcl_multi_icmp_in -p icmpv6 --icmpv6-type echo-request -j ACCEPT
$IP6TABLES -A lan_if_llcl_multi_icmp_out -p icmpv6 --icmpv6-type echo-reply -j ACCEPT


#########################################################################################
# Firewall DHCP client to remote DHCP server traffic
#########################################################################################
if [ "$ISA_DHCP6_CLIENT" = "1" ]; then
    if [ "$RUN_SILENTLY" != "1" ]; then
	    echo "(IPv6)Setting local F/W DHCP client to remote DHCP server rules (WAN side)."
    fi
    # Initialization or rebinding: No lease or Lease time expired
    $IP6TABLES -A lcl_dhcp_client_query -s $EXT_LINKLOCAL_IP \
	    -d $MULTICAST -j ACCEPT
    # DHCP response
    $IP6TABLES -A rmt_dhcp_srv_response -s $LINK_LOCAL \
	    -d $EXT_LINKLOCAL_IP -j ACCEPT
fi


#########################################################################################
# Firewall DHCP server to LAN DHCP client traffic
#########################################################################################
if [ "$ISA_DHCP6_SERVER" = "1" ]; then
    if [ "$RUN_SILENTLY" != "1" ]; then
	    echo "(IPv6)Setting local F/W DHCP server to LAN DHCP client rules (LAN side)."
    fi
    # Initialization or rebinding: No lease or Lease time expired
    $IP6TABLES -A LAN_dhcp_srv_response -s $LOCAL_DHCP_SERVER_LINK_LOCAL -j ACCEPT
    # Lease renewal 
    $IP6TABLES -A LAN_dhcp_client_query -i $LAN_IF \
             -d $LOCAL_DHCP_SERVER_LINK_LOCAL -j ACCEPT
    # Lease renewal response
    $IP6TABLES -A LAN_dhcp_srv_response -s $LOCAL_DHCP_SERVER_LINK_LOCAL -j ACCEPT
fi


#########################################################################################
# Set up the jumps from the built-in INPUT, OUTPUT, and FORWARD chains to our standard 
# user chains
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Creating the DHCP jump rules to the user-defined chains:"
fi

# DHCP Client (when this F/W is a DHCP client to an ISP's DHCP server)
if [ "$ISA_DHCP6_CLIENT" = "1" ]; then
    if [ "$RUN_SILENTLY" != "1" ]; then
	    echo -n "(IPv6) DHCP client, "
    fi
    $IP6TABLES -A INPUT  -i $INTERNET_IF -p udp \
             --sport bootps --dport bootpc -j rmt_dhcp_srv_response
    $IP6TABLES -A OUTPUT -o $INTERNET_IF -p udp \
             --sport bootpc --dport bootps -j lcl_dhcp_client_query
    $IP6TABLES -A INPUT  -i $INTERNET_IF -p udp \
             --sport $DHCP_IPV6_ADVERTISE_UDP_PORT \
	     --dport $DHCP_IPV6_SOLICIT_UDP_PRT -j rmt_dhcp_srv_response
    $IP6TABLES -A OUTPUT -o $INTERNET_IF -p udp \
	    --sport $DHCP_IPV6_SOLICIT_UDP_PRT \
	    --dport $DHCP_IPV6_ADVERTISE_UDP_PORT -j lcl_dhcp_client_query
fi

# DHCP Server (when this F/W is a DHCP server to the internal LAN)
if [ "$ISA_DHCP6_SERVER" = "1" ]; then
    if [ "$RUN_SILENTLY" != "1" ]; then
	    echo "& DHCP server, "
    fi
    $IP6TABLES -A INPUT -i $LAN_IF -p udp \
             --sport bootpc --dport bootps -j LAN_dhcp_client_query
    $IP6TABLES -A OUTPUT -o $LAN_IF -p udp \
             --sport bootps --dport bootpc -j LAN_dhcp_srv_response
    $IP6TABLES -A INPUT -i $LAN_IF -p udp \
             --sport 21302 --dport 21302 -j LAN_dhcp_client_query
    $IP6TABLES -A OUTPUT -o $LAN_IF -p udp \
             --sport 21302 --dport 21302 -j LAN_dhcp_srv_response
    $IP6TABLES -A INPUT -i $LAN_IF -p udp \
             --sport $DHCP_IPV6_SOLICIT_UDP_PRT --dport $DHCP_IPV6_ADVERTISE_UDP_PORT -j LAN_dhcp_client_query
    $IP6TABLES -A OUTPUT -o $LAN_IF -p udp \
             --sport $DHCP_IPV6_SOLICIT_UDP_PRT --dport $DHCP_IPV6_ADVERTISE_UDP_PORT -j LAN_dhcp_srv_response

fi

#########################################################################################
#########################################################################################
# Logging Rules Prior to Dropping by the Default Policy
#########################################################################################
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Creating link local logging before Global IP is established."
fi

##############
# ICMP rules #
##############
$IP6TABLES -A log_in -p icmpv6 ! --icmpv6-type echo-request -m limit --limit 1/sec \
	-j LOG --log-prefix "(IPv6)(D-PG)IN-drop: "

##############
# TCP rules  #
##############
$IP6TABLES -A log_in -p tcp --dport 0:134 -j LOG --log-prefix "(IPv6)(D-PG)IN-drop: "
# Skip Microsoft RPC at 135
$IP6TABLES -A log_in -p tcp --dport 136 -j LOG --log-prefix "(IPv6)(D-PG)IN-drop: "
# Skip Microsoft NETBIOS crap at 137, 138, & 139
#137	netbios-ns	NETBIOS Name Service
#138	netbios-dgm	NETBIOS Datagram Service
#139	netbios-ssn	NETBIOS Session Service
$IP6TABLES -A log_in -p tcp --dport 140:142 -j LOG --log-prefix "(IPv6)(D-PG)IN-drop: "
# skip imap
$IP6TABLES -A log_in -p tcp --dport 144:444 -j LOG --log-prefix "(IPv6)(D-PG)IN-drop: "
# skip microsoft-ds
$IP6TABLES -A log_in -p tcp --dport 446:65535 -j LOG --log-prefix "(IPv6)(D-PG)IN-drop: "

################################
# log outgoing unmatched rules
################################
# Debug: Log rejected outgoing ICMP destination-unreachable packets
$IP6TABLES -A log_out -p icmpv6 \
         --icmpv6-type destination-unreachable \
	 -j LOG --log-prefix "(IPv6)(D-PG)OUT-icmp-dest-unrch-drop: "
$IP6TABLES -A log_out -p icmpv6 \
         --icmpv6-type destination-unreachable -j DROP
# End debug.

# But log everything else
$IP6TABLES -A log_out -j LOG --log-prefix "(IPv6)(D-PG)OUT-drop: "

######################
# log_forward rules  #
######################
# Log everything that did not match an ACCEPT rule before this point
$IP6TABLES -A log_forward -j LOG --log-prefix "(IPv6)(D-PG)FWD-drop: "

#########################################################################################
# Add the link local chains to INPUT and OUTPUT
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Adding link local chains to INPUT and OUTPUT: "
fi

# Link Local routed packets coming from the Internet that are destined to  
# our firewall's multicast
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6) ext if llcl multi in, "
fi
$IP6TABLES -A INPUT -i $INTERNET_IF -s $LINK_LOCAL -d $MULTICAST \
	-j ext_if_llcl_multi_in

# Link Local routed packets coming from the Internet that are destined to  
# our firewall's link local address
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ext if llcl llcl in, "
fi
$IP6TABLES -A INPUT -i $INTERNET_IF -s $LINK_LOCAL -d $LINK_LOCAL \
	-j ext_if_llcl_llcl_in

# Link Local routed packets coming from a link local IP address on the LAN that 
# are destined to our firewall's multicast
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "LAN if llcl multi in, "
fi
$IP6TABLES -A INPUT -i $LAN_IF -s $LINK_LOCAL -d $MULTICAST \
	-j lan_if_llcl_multi_in

# Link Local routed packets coming from a link local IP address on the LAN that 
# are destined to our firewall's link local address
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "LAN if llcl llcl in, "
fi
$IP6TABLES -A INPUT -i $LAN_IF -s $LINK_LOCAL -d $LINK_LOCAL \
	-j lan_if_llcl_llcl_in

# Link Local packets coming from our firewall's Link Local IP address and
# destined to the multicast IP address on the Internet
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6) ext if llcl multi out, "
fi
$IP6TABLES -A OUTPUT -o $INTERNET_IF -s $LINK_LOCAL -d $MULTICAST \
	-j ext_if_llcl_multi_out

# Link Local packets coming from our firewall's Link Local IP address and
# destined to Link Local IP address on the Internet
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ext if llcl llcl out, "
fi
$IP6TABLES -A OUTPUT -o $INTERNET_IF -s $LINK_LOCAL -d $LINK_LOCAL \
	-j ext_if_llcl_llcl_out

# Link Local packets coming from our firewall's Link Local IP address and
# destined to the multicast IP address on the LAN
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "LAN if llcl multi out, "
fi
$IP6TABLES -A OUTPUT -o $LAN_IF -s $LINK_LOCAL -d $MULTICAST \
	-j lan_if_llcl_multi_out

# Link Local packets coming from our firewall's Link Local IP address and
# destined a link local IP address on the LAN
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "LAN if llcl llcl out, "
fi
$IP6TABLES -A OUTPUT -o $LAN_IF -s $LINK_LOCAL -d $LINK_LOCAL \
	-j lan_if_llcl_llcl_out


#########################################################################################
# Add the logging to the bottom of the appropriate built-in chain
#########################################################################################
$IP6TABLES -A INPUT  -j log_in 
$IP6TABLES -A OUTPUT -j log_out 
$IP6TABLES -A FORWARD -j log_forward


#########################################################################################
# Open up the flood gates by dropping the first rule on the input and forward chains,
# which was explicitly set to DROP all traffic (except loopback)
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Restoring normal traffic. (Pre-Global IP establishment)"
    	logger "$(basename "$0")(IPv6): Rules applied. Restoring normal traffic. (Pre-Global IP establishment)"
fi

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Removing DROP rule on INPUT chain "
fi
$IP6TABLES -D INPUT 1

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Link Local rules done at:" `date`
    	logger "$(basename "$0")(IPv6): Link Local rules done."
fi

echo "--------------------------"


######################################################################
######################################################################
# WAN side definitions (dynamically created)
######################################################################
######################################################################
INTERNET_IP=""
IP_ADDR_RETRY_COUNT=0		        # Current IP Address DHCP resolution retry count
IP_ADDR_RETRY_MAX=2		            # Maximum number of times to retry before giving up
IP_ADDR_RETRY_SLEEP_TIME=10 		# Seconds to sleep between retrys

getIpv6ExternalIPAddress() {
	INTERNET_IP=$(/sbin/ip -o -6 addr list $INTERNET_IF | egrep -v fe80 | awk '{print $4}')
	IP_ADDR_RETRY_COUNT=$((IP_ADDR_RETRY_COUNT+1))
}

getIpv6ExternalIPAddress
while [ -z "$INTERNET_IP" -a $IP_ADDR_RETRY_COUNT -le $IP_ADDR_RETRY_MAX ]; do
    echo "(IPv6)Internet IPv6 IP address not yet known. Sleeping for $IP_ADDR_RETRY_SLEEP_TIME seconds."
	sleep $IP_ADDR_RETRY_SLEEP_TIME	
	getIpv6ExternalIPAddress
done

if [ -z "$INTERNET_IP" ]; then
    echo "(IPv6)Internet IPv6 IP address not resolved. Exiting."
    logger "$(basename "$0")(IPv6): Internet IPv6 IP address not resolved. Exiting."
    exit 1
fi
echo '(IPv6)            INTERNET_IP: '\'$INTERNET_IP\'
logger "$(basename "$0")(IPv6): Internet IP: $INTERNET_IP"

# Our Internet IP without the mask
INTERNET_IP_SANS_MASK=$(echo $INTERNET_IP | cut -d/ -f1)
echo '(IPv6)  INTERNET_IP_SANS_MASK: '\'$INTERNET_IP_SANS_MASK\'
logger "$(basename "$0")(IPv6): Internet IP sans mask: $INTERNET_IP_SANS_MASK"

# Our subnet prefix length
INTERNET_PREFIX_LENGTH=$(/sbin/ip -o -6 addr list $INTERNET_IF | egrep -v fe80 | awk '{print $4}' | cut -d/ -f2)
echo '(IPv6) INTERNET_PREFIX_LENGTH: '\'$INTERNET_PREFIX_LENGTH\'
logger "$(basename "$0")(IPv6): Internet Prefix Length: $INTERNET_PREFIX_LENGTH"

# Our Internet (WAN) subnet prefix
INTERNET_SUBNET=$(/sbin/ip -6 route list dev enp2s0 | egrep -v "fe80" | awk '{print $1}')
echo '(IPv6)        INTERNET_SUBNET: '\'$INTERNET_SUBNET\'
logger "$(basename "$0")(IPv6): Internet subnet prefix: $INTERNET_SUBNET"


######################################################################
######################################################################
# LAN side definitions (dynamically created)
######################################################################
######################################################################
LAN_IP=""

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


#########################################################################################
# Server IP addresses and definitions for secondary services
#########################################################################################

#########################################################################################
# Firewall's DHCP server over global LAN IP address
#########################################################################################
LOCAL_DHCP_SERVER=$LAN_IP                	# Our firewall's DHCP server on the LAN side

#########################################################################################
# DNS over global IP address
#########################################################################################
LOCAL_NAMESERVER=$INTERNET_IP              	# My Local Caching/Forwarding DNS server on the outside IF
LOCAL_NAMESERVER_INT=$LAN_IP				# My Local Caching/Forwarding DNS server on the inside LAN IF
LOCAL_NAMESERVER_LINKLOCAL_INT=$INT_LINKLOCAL_GATEWAY  # My local caching/forwarding DNS server on the link local IF	

#########################################################################################
# SMTP
#########################################################################################
ALT_SMTPS_PORT="587"		    # Alternate listening port for secure SMTP (default is 465)
REMOTE_SMTP_SERVER="2607:f8b0:4004:c06::11"  # external mail server (mail.google.com)

#########################################################################################
# NTP
#########################################################################################
# The timeserver variables are placeholders. Current NTP requests are allowed from any
# machine inside or including the firewall.
TIME_SERVER1="2610:20:6f15:15::27"          # NTP server time-d-g.nist.gov Gaithersburg, Maryland
TIME_SERVER2="2610:20:6f15:15::26"          # NTP server time-e-g.nist.gov Gaithersburg, Maryland
TIME_SERVER3="2610:20:6f97:97::4"           # NTP server time-d-wwv.nist.gov WWV, Fort Collins, Colorado
TIME_SERVER4="2610:20:6f97:97::6"           # NTP server time-e-wwv.nist.gov WWV, Fort Collins, Colorado
TIME_SERVER5="2610:20:6f96:96::4"           # NTP server time-d-b.nist.gov NIST, Boulder, Colorado
TIME_SERVER6="2610:20:6f96:96::6"           # NTP server time-e-b.nist.gov NIST, Boulder, Colorado
NEWS_SERVER=$ANYWHERE                       # News server allowed at any IP address

#########################################################################################
# Other Internal Servers & Ports
#########################################################################################
STEAMDECK_DOCK="${LAN_SUBNET_NO_MASK}500"       # Steamdeck in Dock with Ethernet
STEAMDECK_WL="${LAN_SUBNET_NO_MASK}502"         # Steamdeck wireless
MYLAPTOP="${LAN_SUBNET_NO_MASK}504"             # Windows Laptop (via wireless)
GAMINGPC="${LAN_SUBNET_NO_MASK}506"             # The Beast
FILESERVER="${LAN_SUBNET_NO_MASK}508"           # File Server and Backup
IPHONE="${LAN_SUBNET_NO_MASK}50a"               # iPhone
ORBI="${LAN_SUBNET_NO_MASK}50c"                 # Netgear Orbi base as a mesh Wireless Access Point
ECOBEE3="${LAN_SUBNET_NO_MASK}50e"              # Ecobee 3 Thermostat
SAMSUNGS23U="${LAN_SUBNET_NO_MASK}510"          # Samsung Galaxy S23 Ultra (Work)
SAMSUNGS24="${LAN_SUBNET_NO_MASK}512"           # Samsung Galaxy S24
FAMROOMECHO="${LAN_SUBNET_NO_MASK}514"          # Amazon Echo 4th Gen (Family Room)
OFFICEECHO="${LAN_SUBNET_NO_MASK}516"           # Amazon Echo DOT Gen 4 (Office)
GALAXYTAB="${LAN_SUBNET_NO_MASK}518"            # Galaxay Tab
FRONTLIGHTS="${LAN_SUBNET_NO_MASK}51a"          # Smart swith for front lights
KINDLE="${LAN_SUBNET_NO_MASK}51c"               # Amazon Kindle
ROKU="${LAN_SUBNET_NO_MASK}51e"                 # Roku Ultra
VPN_TUNNEL="${LAN_SUBNET_NO_MASK}520"           # System neededing a VPN Tunnel
WIRELESSPLUG1="${LAN_SUBNET_NO_MASK}522"        # 2.4GHz wireless plug #1
ORBISATELLITE="${LAN_SUBNET_NO_MASK}524"        # Netgear Orbi satellite
GUESTGAMER="${LAN_SUBNET_NO_MASK}526"           # Guest gaming box
WIRELESSPLUG2="${LAN_SUBNET_NO_MASK}528"        # 2.4GHz wireless plug #2
NINTENDOSWITCH="${LAN_SUBNET_NO_MASK}52a"       # Nintendo Switch
PRINTER="${LAN_SUBNET_NO_MASK}52c"              # Networked Printer


VPN_CLIENT_MAIL_PORTS="2222:2223"   # VPN server port
PRINTER_CTRL_PORT1="161"            # some port used by the printer
PRINTER_CTRL_PORT2="631"            # some port used by the printer
PRINTER_TCP_PRINTING="9100"         # TCP port for network printing

######################################################################
# Common Port Numbers
######################################################################
# Google services
GOOGLE_TALK_UDP_PORT="3478"
GOOGLE_TALK_UDP_PORT_RNG="19302:19309"
GOOGLE_TALK_UDP_PORT_RNG2="26500:26501"
GOOGLE_TALK_TCP_PORT="5222"
GGOGLE_TALK_SERVER_RANGE="2001:4860:4864:2::0/64"
GOOGLE_PLAYSTORE_TCP_PORT="5228"

# Definitions for special ports rather than addresses
WEB_ALT_PORT="81"                   # Alternate port for some web servers
WEB_PROXY_PORT="8080"               # ISP web proxy port, if any,
				    # typically 8008 or 8080
WEB_PROXY_PORT2="8000"              # ISP web proxy port, if any,
WEB_ALT_HTTPS_PORT="8443"           # ISP alternate https port
WOW_MOBILE_ARMORY="8780"            # ISP alternate https port
VT_ALT_HTTPS_PORT="2443"            # VT alternate https port

LDAP_PORT="389"                     # LDAP service
PRIVPORTS="0:1023"                  # wellknown, privileged port range
UNPRIVPORTS="1024:65535"            # unprivileged port range

# Other well-known ports
SOCKS_PORT="1080"                   # (TCP) socks
NFS_PORT="2049"                     # (TCP/UDP) NFS
SQUID_PORT="3128"
LOCKD_PORT="4045"
# X Windows port allocation begins at 6000 and increments
# for each additional server running from 6000 to 6063.
XWINDOW_PORTS="6000:6023"           # (TCP) X windows
# traceroute usually uses -S 32769:65535 -D 33434:33523
TRACEROUTE_SRC_PORTS="32769:65535"
TRACEROUTE_DEST_PORTS="33434:33523"


#########################################################################################
# Firewall rules for all LAN clients
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Establishing common LAN client IP rules: "
fi


if [ "$RUN_SILENTLY" != "1" ]; then
    echo "(IPv6)Adding additional link local chains to INPUT and OUTPUT: "
fi

# Link Local routed packets coming from a subnet IP address on our LAN that
# are destined to our firewall's link local address
if [ "$RUN_SILENTLY" != "1" ]; then
    echo -n "(IPv6) LAN if subnet llcl in, "
fi
$IP6TABLES -A INPUT -i $LAN_IF -s $LAN_SUBNET -d $INT_LINKLOCAL_IP \
    -j lan_if_subnet_llcl_in

# Routed packets coming from a subnet IP address on our LAN that
# are destined to the multicast IP range
if [ "$RUN_SILENTLY" != "1" ]; then
    echo -n "LAN if subnet multicast in, "
fi
$IP6TABLES -A INPUT -i $LAN_IF -s $LAN_SUBNET -d $MULTICAST \
    -j lan_if_subnet_multi_in

# Link Local packets coming from our firewall's Link Local IP address and
# destined a device on our LAN that has a permanent or temporary IP address
# on our LAN's subnet
if [ "$RUN_SILENTLY" != "1" ]; then
    echo "& LAN if llcl subnet out "
fi
$IP6TABLES -A OUTPUT -o $LAN_IF -s $INT_LINKLOCAL_IP -d $LAN_SUBNET \
    -j lan_if_llcl_subnet_out


#########################################################################################
# Domain Name Server - DNS (local DNS server making queries to 
# remote, trusted DNS servers and remote, trusted DNS servers
# making queries to local DNS server)
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)DNS (local-to-trusted), "
fi

#####################
# Set up the chains #
#####################
# Set up the jump to the chains for UDP DNS requests
$IP6TABLES -A ext_if_out -p udp --sport domain --dport domain \
	-j lcl_dns_srv_to_trust_dns_srv
$IP6TABLES -A ext_if_in -p udp --sport domain --dport domain \
	-j lcl_dns_srv_fm_trust_dns_srv
$IP6TABLES -A ext_if_in -p udp --sport domain --dport $UNPRIVPORTS \
	-j lcl_dns_srv_fm_trust_dns_srv
$IP6TABLES -A ext_if_out -p udp --sport domain-s --dport domain-s \
	-j lcl_dns_srv_to_trust_dns_srv
$IP6TABLES -A ext_if_in -p udp --sport domain-s --dport domain-s \
	-j lcl_dns_srv_fm_trust_dns_srv
$IP6TABLES -A ext_if_in -p udp --sport domain-s --dport $UNPRIVPORTS \
	-j lcl_dns_srv_fm_trust_dns_srv
$IP6TABLES -A ext_if_out -p udp --sport $MULTICAST_DNS_UDP_PORT --dport $MULTICAST_DNS_UDP_PORT \
	-j lcl_dns_srv_to_trust_dns_srv
$IP6TABLES -A ext_if_in -p udp --sport $MULTICAST_DNS_UDP_PORT --dport $MULTICAST_DNS_UDP_PORT \
	-j lcl_dns_srv_fm_trust_dns_srv

# Set up the jump to the chains for TCP DNS requests
$IP6TABLES -A ext_if_out -p tcp --sport $UNPRIVPORTS --dport domain \
	-j lcl_dns_srv_to_trust_dns_srv
$IP6TABLES -A ext_if_in -p tcp ! --syn --sport domain --dport $UNPRIVPORTS \
	-j lcl_dns_srv_fm_trust_dns_srv
$IP6TABLES -A ext_if_out -p tcp --sport $UNPRIVPORTS --dport domain-s \
	-j lcl_dns_srv_to_trust_dns_srv
$IP6TABLES -A ext_if_in -p tcp ! --syn --sport domain-s --dport $UNPRIVPORTS \
	-j lcl_dns_srv_fm_trust_dns_srv

####################
# Set up the rules #
####################
# Add the rules for DNS requests/reponses going to trusted DNS servers
# from the firewall
$IP6TABLES -A lcl_dns_srv_to_trust_dns_srv \
         -d $NAMESERVER_1 -j ACCEPT
$IP6TABLES -A lcl_dns_srv_to_trust_dns_srv \
         -d $NAMESERVER_2 -j ACCEPT
$IP6TABLES -A lcl_dns_srv_to_trust_dns_srv \
         -d $NAMESERVER_3 -j ACCEPT
$IP6TABLES -A lcl_dns_srv_to_trust_dns_srv \
         -d $NAMESERVER_4 -j ACCEPT

$IP6TABLES -A lcl_dns_srv_fm_trust_dns_srv \
         -s $NAMESERVER_1 -j ACCEPT
$IP6TABLES -A lcl_dns_srv_fm_trust_dns_srv \
         -s $NAMESERVER_2 -j ACCEPT
$IP6TABLES -A lcl_dns_srv_fm_trust_dns_srv \
         -s $NAMESERVER_3 -j ACCEPT
$IP6TABLES -A lcl_dns_srv_fm_trust_dns_srv \
         -s $NAMESERVER_4 -j ACCEPT

###############################################################
# Domain Name Server - DNS (LAN machines making queries to the
# local DNS server or one of the remote trusted servers)
###############################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "DNS and Multicast (LAN-to-local), "
fi

#####################
# Set up the chains #
#####################
# Chains for UDP requests
$IP6TABLES -A lan_if_out -p udp --sport domain --dport $UNPRIVPORTS \
	-j trusted_dns_srv_LAN_response
$IP6TABLES -A lan_if_out -p udp --sport domain-s --dport $UNPRIVPORTS \
	-j trusted_dns_srv_LAN_response
$IP6TABLES -A lan_if_out -p udp --sport $MULTICAST_DNS_UDP_PORT --dport $MULTICAST_DNS_UDP_PORT \
	-j trusted_dns_srv_LAN_response
$IP6TABLES -A lan_if_in -p udp --sport $UNPRIVPORTS --dport domain \
	-j trusted_dns_srv_LAN_query
$IP6TABLES -A lan_if_in -p udp --sport $UNPRIVPORTS --dport domain-s \
	-j trusted_dns_srv_LAN_query
$IP6TABLES -A lan_if_in -p udp --sport $MULTICAST_DNS_UDP_PORT --dport $MULTICAST_DNS_UDP_PORT \
	-j trusted_dns_srv_LAN_query
$IP6TABLES -A ext_if_lan_out -p udp --sport domain --dport $UNPRIVPORTS \
	-j trusted_dns_srv_LAN_response
$IP6TABLES -A ext_if_lan_out -p udp --sport domain-s --dport $UNPRIVPORTS \
	-j trusted_dns_srv_LAN_response
$IP6TABLES -A ext_if_lan_out -p udp --sport $MULTICAST_DNS_UDP_PORT --dport $MULTICAST_DNS_UDP_PORT \
	-j trusted_dns_srv_LAN_response
$IP6TABLES -A ext_if_lan_in -p udp --sport $UNPRIVPORTS --dport domain \
	-j trusted_dns_srv_LAN_query
$IP6TABLES -A ext_if_lan_in -p udp --sport $UNPRIVPORTS --dport domain-s \
	-j trusted_dns_srv_LAN_query
$IP6TABLES -A ext_int -p udp --sport domain --dport $UNPRIVPORTS \
	-j trusted_dns_srv_LAN_response
$IP6TABLES -A ext_int -p udp --sport domain-s --dport $UNPRIVPORTS \
	-j trusted_dns_srv_LAN_response
$IP6TABLES -A ext_int -p udp --sport $MULTICAST_DNS_UDP_PORT --dport $MULTICAST_DNS_UDP_PORT \
	-j trusted_dns_srv_LAN_response
$IP6TABLES -A int_ext -p udp --sport $UNPRIVPORTS --dport domain \
	-j trusted_dns_srv_LAN_query
$IP6TABLES -A int_ext -p udp --sport $UNPRIVPORTS --dport domain-s \
	-j trusted_dns_srv_LAN_query
$IP6TABLES -A int_ext -p udp --sport $MULTICAST_DNS_UDP_PORT --dport $MULTICAST_DNS_UDP_PORT \
	-j trusted_dns_srv_LAN_query

# Chains for TCP requests
$IP6TABLES -A lan_if_out -p tcp --sport domain --dport $UNPRIVPORTS \
	-j trusted_dns_srv_LAN_response
$IP6TABLES -A lan_if_in -p tcp --sport $UNPRIVPORTS --dport domain \
	-j trusted_dns_srv_LAN_query
$IP6TABLES -A ext_if_lan_out -p tcp --sport domain --dport $UNPRIVPORTS \
	-j trusted_dns_srv_LAN_response
$IP6TABLES -A ext_if_lan_in -p tcp --sport $UNPRIVPORTS --dport domain \
	-j trusted_dns_srv_LAN_query
$IP6TABLES -A lan_if_out -p tcp --sport domain-s --dport $UNPRIVPORTS \
	-j trusted_dns_srv_LAN_response
$IP6TABLES -A lan_if_in -p tcp --sport $UNPRIVPORTS --dport domain-s \
	-j trusted_dns_srv_LAN_query
$IP6TABLES -A ext_if_lan_out -p tcp --sport domain-s --dport $UNPRIVPORTS \
	-j trusted_dns_srv_LAN_response
$IP6TABLES -A ext_if_lan_in -p tcp --sport $UNPRIVPORTS --dport domain-s \
	-j trusted_dns_srv_LAN_query

####################
# Set up the rules #
####################
# Unlimited link local traffic on the LAN IF to our LAN's IP
$IP6TABLES -A INPUT  -i $LAN_IF -s $LINK_LOCAL -d $LAN_IP \
	-j ACCEPT
$IP6TABLES -A OUTPUT -o $LAN_IF -s $LAN_IP -d $LINK_LOCAL \
	-j ACCEPT

# Add the rules for multicast requests and responses
$IP6TABLES -A trusted_dns_srv_LAN_query -p udp -s $LAN_IP -d $MULTICAST \
	-j ACCEPT
$IP6TABLES -A trusted_dns_srv_LAN_response -p udp -s $MULTICAST -d $LAN_IP \
	-j ACCEPT
$IP6TABLES -A trusted_dns_srv_LAN_query -p udp -s $INTERNET_IP -d $MULTICAST \
	-j ACCEPT
$IP6TABLES -A trusted_dns_srv_LAN_response -p udp -s $MULTICAST -d $INTERNET_IP \
	-j ACCEPT
$IP6TABLES -A OUTPUT -o $LAN_IF -s $LAN_IP -d $MULTICAST \
    -j lan_if_fwl_multi_out

# Add the rules for DNS requests going to trusted DNS servers
$IP6TABLES -A trusted_dns_srv_LAN_query \
         -d $LOCAL_NAMESERVER -j ACCEPT
$IP6TABLES -A trusted_dns_srv_LAN_query \
         -d $LOCAL_NAMESERVER_INT -j ACCEPT
$IP6TABLES -A trusted_dns_srv_LAN_query \
         -d $NAMESERVER_1 -j ACCEPT
$IP6TABLES -A trusted_dns_srv_LAN_query \
         -d $NAMESERVER_2 -j ACCEPT
$IP6TABLES -A trusted_dns_srv_LAN_query \
         -d $NAMESERVER_3 -j ACCEPT
$IP6TABLES -A trusted_dns_srv_LAN_query \
         -d $NAMESERVER_4 -j ACCEPT

# Add the rules for DNS reponses coming from trusted DNS servers
$IP6TABLES -A trusted_dns_srv_LAN_response \
         -s $LOCAL_NAMESERVER -j ACCEPT
$IP6TABLES -A trusted_dns_srv_LAN_response \
         -s $LOCAL_NAMESERVER_INT -j ACCEPT
$IP6TABLES -A trusted_dns_srv_LAN_response \
         -s $NAMESERVER_1 -j ACCEPT
$IP6TABLES -A trusted_dns_srv_LAN_response \
         -s $NAMESERVER_2 -j ACCEPT
$IP6TABLES -A trusted_dns_srv_LAN_response \
         -s $NAMESERVER_3 -j ACCEPT
$IP6TABLES -A trusted_dns_srv_LAN_response \
         -s $NAMESERVER_4 -j ACCEPT

#########################################################################################
# Domain Name Server - DNS (local DNS server making queries to 
# remote, untrusted DNS servers and remote, untrusted DNS servers
# giving responses to local DNS server)
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6) DNS (local-to-untrusted), "
fi

#####################
# Set up the chains #
#####################
# Set up the jump to the chains for UDP requests
$IP6TABLES -A ext_if_out -p udp --sport $UNPRIVPORTS --dport domain \
	-j rmt_dns_srv_query
$IP6TABLES -A ext_if_out -p udp --sport $UNPRIVPORTS --dport domain-s \
	-j rmt_dns_srv_query
$IP6TABLES -A ext_if_in -p udp --sport domain --dport $UNPRIVPORTS \
	-j rmt_dns_srv_response
$IP6TABLES -A ext_if_in -p udp --sport domain-s --dport $UNPRIVPORTS \
	-j rmt_dns_srv_response

# Set up the jump to the chains for TCP requests
$IP6TABLES -A ext_if_out -p tcp --sport $UNPRIVPORTS --dport domain \
	-j rmt_dns_srv_query
$IP6TABLES -A ext_if_out -p tcp --sport $UNPRIVPORTS --dport domain-s \
	-j rmt_dns_srv_query
$IP6TABLES -A ext_if_in -p tcp ! --syn --sport domain --dport $UNPRIVPORTS \
	-j rmt_dns_srv_response
$IP6TABLES -A ext_if_in -p tcp ! --syn --sport domain-s --dport $UNPRIVPORTS \
	-j rmt_dns_srv_response

####################
# Set up the rules #
####################
# Add the rules for DNS requests/reponses going to trusted DNS servers
$IP6TABLES -A rmt_dns_srv_query -j ACCEPT
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A rmt_dns_srv_response -p udp -m state --state ESTABLISHED,RELATED \
	     -j ACCEPT
fi

#########################################################################################
# Domain Name Server - DNS (non-trusted Internet machines  
# making queries to the local DNS server)
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& DNS (Internet-to-local) "
fi

#####################
# Set up the chains #
#####################
# Chains for UDP requests
$IP6TABLES -A ext_if_in -p udp --sport $UNPRIVPORTS --dport domain \
	-j lcl_dns_srv_rmt_query
$IP6TABLES -A ext_if_out -p udp --sport domain --dport $UNPRIVPORTS \
	-j lcl_dns_srv_rmt_response
$IP6TABLES -A ext_if_in -p udp --sport domain --dport domain \
	-j lcl_dns_srv_rmt_query
$IP6TABLES -A ext_if_out -p udp --sport domain --dport domain \
	-j lcl_dns_srv_rmt_response
$IP6TABLES -A ext_if_in -p udp --sport $UNPRIVPORTS --dport domain-s \
	-j lcl_dns_srv_rmt_query
$IP6TABLES -A ext_if_out -p udp --sport domain-s --dport $UNPRIVPORTS \
	-j lcl_dns_srv_rmt_response
$IP6TABLES -A ext_if_in -p udp --sport domain-s --dport domain-s \
	-j lcl_dns_srv_rmt_query
$IP6TABLES -A ext_if_out -p udp --sport domain-s --dport domain-s \
	-j lcl_dns_srv_rmt_response

# Chains for TCP requests
$IP6TABLES -A ext_if_in -p tcp --syn --sport $UNPRIVPORTS --dport domain \
	-j lcl_dns_srv_rmt_query
$IP6TABLES -A ext_if_out -p tcp --syn --sport domain --dport $UNPRIVPORTS \
	-j lcl_dns_srv_rmt_response
$IP6TABLES -A ext_if_in -p tcp --syn --sport $UNPRIVPORTS --dport domain-s \
	-j lcl_dns_srv_rmt_query
$IP6TABLES -A ext_if_out -p tcp --syn --sport domain-s --dport $UNPRIVPORTS \
	-j lcl_dns_srv_rmt_response

####################
# Set up the rules #
####################
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	# Add the rules for DNS requests from the Internet
	$IP6TABLES -A lcl_dns_srv_rmt_query -d $LOCAL_NAMESERVER -m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lcl_dns_srv_rmt_query -d $LOCAL_NAMESERVER -j ACCEPT
$IP6TABLES -A lcl_dns_srv_rmt_response -s $LOCAL_NAMESERVER -j ACCEPT


#########################################################################################
# Firewall and LAN TCP clients to remote TCP servers for those remote services that both
# the firewall and the LAN machines should be able to use. There will also likely
# be services (e.g., the DNS service above) that the firewall has access to that the
# LAN machines do not. There is also a separate set for UDP servers.
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)F/W & LAN TCP clients to Internet: "
fi

#####################
# Set up the chains #
#####################
# A TCP client on the firewall talking to remote server
$IP6TABLES -A ext_if_out -p tcp --sport $UNPRIVPORTS -j lcl_tcp_client_request
$IP6TABLES -A ext_if_in -p tcp ! --syn --dport $UNPRIVPORTS -j rmt_tcp_srv_response
# A TCP client on the LAN talking to a remote server
$IP6TABLES -A int_ext -p tcp --sport $UNPRIVPORTS -j lcl_tcp_client_request
$IP6TABLES -A ext_int -p tcp ! --syn --dport $UNPRIVPORTS -j rmt_tcp_srv_response

####################
# Set up the rules #
####################

#####################################################################
# Rules for all devices on same source (e.g., Internal LAN traffic) #
#####################################################################
# SSH client talking using SSL to any remote SSH server daemon
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "SSH, "
fi
# Our ssh clients talking to remote SSH servers
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lcl_tcp_client_request -p tcp --dport ssh --syn -m state --state NEW \
	     -j ACCEPT
fi
$IP6TABLES -A lcl_tcp_client_request -p tcp --dport ssh \
	 -j ACCEPT
$IP6TABLES -A rmt_tcp_srv_response -p tcp ! --syn --sport ssh \
	 -j ACCEPT

# Client rules for HTTP, HTTPS, AUTH, and FTP control requests 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "http (80,81,8080,8443,2443,4885), https, whois, auth, "
	echo -n "(IPv6) FTP control, FTP data, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lcl_tcp_client_request -p tcp -m multiport \
    	--destination-port http,whois,$WEB_ALT_PORT,$WEB_PROXY_PORT,$WEB_PROXY_PORT2,$WEB_ALT_HTTPS_PORT,$VT_ALT_HTTPS_PORT,https,auth,ftp,ftp-data,ftps,ftps-data,4885 \
        --syn -m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lcl_tcp_client_request -p tcp -m multiport \
	--destination-port http,$WEB_ALT_PORT,$WEB_PROXY_PORT,$WEB_PROXY_PORT2,$WEB_ALT_HTTPS_PORT,https,auth,ftp,ftp-data,ftps,ftps-data \
        -j ACCEPT
$IP6TABLES -A rmt_tcp_srv_response -p tcp -m multiport \
	--source-port http,$WEB_ALT_PORT,$WEB_PROXY_PORT,$WEB_PROXY_PORT2,$WEB_ALT_HTTPS_PORT,https,auth,ftp,ftp-data,ftps,ftps-data \
        -j ACCEPT
$IP6TABLES -A rmt_tcp_srv_response -p udp --source-port https \
        -j ACCEPT
$IP6TABLES -A rmt_tcp_srv_response -p tcp --sport ftp-data \
        -j ACCEPT
$IP6TABLES -A rmt_tcp_srv_response -p tcp --sport ftps-data \
        -j ACCEPT

# POP3 and IMAP2 client
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "POP3, IMAP2, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lcl_tcp_client_request -p tcp -m multiport --destination-port pop3,imap2 \
             --syn -m state --state NEW \
             -j ACCEPT
fi
$IP6TABLES -A lcl_tcp_client_request -p tcp -m multiport --destination-port pop3,imap2 \
         -j ACCEPT
$IP6TABLES -A rmt_tcp_srv_response -p tcp -m multiport --source-port pop3,imap2 ! --syn  \
         -j ACCEPT

# Secure POP client
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "pop3s, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lcl_tcp_client_request -p tcp --dport pop3s \
             --syn -m state --state NEW \
             -j ACCEPT
fi
$IP6TABLES -A lcl_tcp_client_request -p tcp --dport pop3s \
         -j ACCEPT
$IP6TABLES -A rmt_tcp_srv_response -p tcp ! --syn --sport pop3s  \
         -j ACCEPT

# Secure IMAP client
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "imaps, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lcl_tcp_client_request -p tcp --dport imaps \
             --syn -m state --state NEW \
             -j ACCEPT
fi
$IP6TABLES -A lcl_tcp_client_request -p tcp --dport imaps \
         -j ACCEPT
$IP6TABLES -A rmt_tcp_srv_response -p tcp ! --syn --sport imaps  \
         -j ACCEPT

# SMTP mail client
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "smtp, smtps, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lcl_tcp_client_request -p tcp -d $REMOTE_SMTP_SERVER --dport smtp \
             --syn -m state --state NEW \
             -j ACCEPT
fi
$IP6TABLES -A lcl_tcp_client_request -p tcp -d $REMOTE_SMTP_SERVER --dport smtp \
	-j ACCEPT
$IP6TABLES -A rmt_tcp_srv_response -p tcp ! --syn -s $REMOTE_SMTP_SERVER --sport smtp  \
        -j ACCEPT
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lcl_tcp_client_request -p tcp -d $REMOTE_SMTP_SERVER --dport smtps \
             --syn -m state --state NEW \
             -j ACCEPT
fi
$IP6TABLES -A lcl_tcp_client_request -p tcp -d $REMOTE_SMTP_SERVER --dport smtps \
	-j ACCEPT
$IP6TABLES -A rmt_tcp_srv_response -p tcp ! --syn -s $REMOTE_SMTP_SERVER --sport smtps \
        -j ACCEPT
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lcl_tcp_client_request -p tcp -d $REMOTE_SMTP_SERVER --dport $ALT_SMTPS_PORT \
             --syn -m state --state NEW \
             -j ACCEPT
fi
$IP6TABLES -A lcl_tcp_client_request -p tcp -d $REMOTE_SMTP_SERVER --dport $ALT_SMTPS_PORT \
	-j ACCEPT
$IP6TABLES -A rmt_tcp_srv_response -p tcp ! --syn -s $REMOTE_SMTP_SERVER --sport $ALT_SMTPS_PORT \
        -j ACCEPT

# SNMP (requires UDP connections as well)
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "SNMP, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lcl_tcp_client_request -p tcp -d $NEWS_SERVER --dport snmp \
             --syn -m state --state NEW \
             -j ACCEPT
fi
$IP6TABLES -A lcl_tcp_client_request -p tcp -d $NEWS_SERVER --dport snmp \
         -j ACCEPT
$IP6TABLES -A rmt_tcp_srv_response -p tcp ! --syn -s $NEWS_SERVER --sport snmp  \
         -j ACCEPT

# Usenet news client
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& Usenet News, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lcl_tcp_client_request -p tcp -d $NEWS_SERVER --dport nntp \
             --syn -m state --state NEW \
             -j ACCEPT
fi
$IP6TABLES -A lcl_tcp_client_request -p tcp -d $NEWS_SERVER --dport nntp \
         -j ACCEPT
$IP6TABLES -A rmt_tcp_srv_response -p tcp ! --syn -s $NEWS_SERVER --sport nntp  \
         -j ACCEPT
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lcl_tcp_client_request -p tcp -d $NEWS_SERVER --dport nntps \
             --syn -m state --state NEW \
             -j ACCEPT
fi
$IP6TABLES -A lcl_tcp_client_request -p tcp -d $NEWS_SERVER --dport nntps \
         -j ACCEPT
$IP6TABLES -A rmt_tcp_srv_response -p tcp ! --syn -s $NEWS_SERVER --sport nntps \
         -j ACCEPT


#########################################################################################
# Internal LAN UDP clients to services that appear on the firewall machine (whether 
# that's where they truly are or not) There is also a separate set for UDP servers.
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)LAN UDP clts->Local svcs, "
fi
# A UDP client on the LAN talking to a local server on the internal inteface
$IP6TABLES -A lan_if_in -p udp -s $LAN_SUBNET --sport $UNPRIVPORTS \
	-j LAN_udp_client_request
$IP6TABLES -A lan_if_out -p udp --dport $UNPRIVPORTS \
	-j udp_srv_LAN_response
$IP6TABLES -A lan_if_in -p udp -s $LAN_SUBNET --sport $MULTICAST_DNS_UDP_PORT \
	-j LAN_udp_client_request
$IP6TABLES -A lan_if_out -p udp --dport $MULTICAST_DNS_UDP_PORT \
	-j udp_srv_LAN_response

# Multicast DNS
if [ "$RUN_SILENTLY" != "1" ]; then
	echo  "& Multicast DNS "
fi
$IP6TABLES -A LAN_udp_client_request -p udp --dport $MULTICAST_DNS_UDP_PORT \
         -j ACCEPT
$IP6TABLES -A udp_srv_LAN_response -p udp --sport $MULTICAST_DNS_UDP_PORT  \
         -j ACCEPT

# Some authentication servers
$IP6TABLES -A LAN_udp_client_request -p udp \
         --destination-port https \
         -j ACCEPT
$IP6TABLES -A udp_srv_LAN_response -p udp \
         --source-port https \
         -j ACCEPT


#########################################################################################
# Internal LAN TCP clients to services that appear on the firewall machine (whether 
# that's where they truly are or not) There is also a separate set for UDP servers.
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)LAN TCP clts->F/W svcs: "
fi

#####################
# Set up the chains #
#####################
# A TCP client on the LAN talking to a local server on the internal interface
$IP6TABLES -A lan_if_in -p tcp -s $LAN_SUBNET --sport $UNPRIVPORTS \
	-j LAN_tcp_client_request
$IP6TABLES -A lan_if_out -p tcp ! --syn -d $LAN_SUBNET --dport $UNPRIVPORTS \
	-j tcp_srv_LAN_response
# special rule to allow ssh to new server machine at its temp IP addr
$IP6TABLES -A lan_if_out -p tcp -s $LAN_IP --sport $UNPRIVPORTS \
	-d $LAN_SUBNET --dport ssh \
	-j ACCEPT
# A TCP client on the LAN talking to a local server on the external interface via the
#  FORWARD chain. (This should be considered "differently" than requests on the public
#  IP from the INPUT chain
$IP6TABLES -A ext_if_lan_in -p tcp -s $LAN_SUBNET --sport $UNPRIVPORTS \
	-j LAN_tcp_client_request
$IP6TABLES -A ext_if_lan_out -p tcp ! --syn -d $LAN_SUBNET --dport $UNPRIVPORTS \
	-j tcp_srv_LAN_response

####################
# Set up the rules #
####################
# SSH client talking using SSL to any remote SSH server daemon
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)SSH, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A LAN_tcp_client_request -p tcp --dport ssh --syn -m state --state NEW \
	     -j ACCEPT
fi
$IP6TABLES -A LAN_tcp_client_request -p tcp --dport ssh \
	 -j ACCEPT
$IP6TABLES -A tcp_srv_LAN_response -p tcp ! --syn --sport ssh \
	 -j ACCEPT

# Client rules for HTTP, HTTPS, & AUTH requests 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)& HTTP, HTTPS, AUTH "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A LAN_tcp_client_request -p tcp \
             -m multiport --destination-port http,https,auth \
             --syn -m state --state NEW \
	     -j ACCEPT
fi
$IP6TABLES -A LAN_tcp_client_request -p tcp \
         -m multiport --destination-port http,https,auth \
         -j ACCEPT
$IP6TABLES -A tcp_srv_LAN_response -p tcp \
         -m multiport --source-port http,https,auth  ! --syn \
         -j ACCEPT


#########################################################################################
# A remote (potentially) untrusted internet client talking to a Local TCP server.
# There is also a separate set for UDP servers.
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Internet TCP clts->F/W svcs: "
fi

#####################
# Set up the chains #
#####################
$IP6TABLES -A ext_if_in -p tcp --sport $UNPRIVPORTS -j rmt_tcp_client_request
$IP6TABLES -A ext_if_out -p tcp ! --syn --dport $UNPRIVPORTS -j lcl_tcp_srv_response

####################
# Set up the rules #
####################
# SSH server
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)SSH "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A rmt_tcp_client_request -p tcp --dport ssh \
		-m state --state NEW -j ACCEPT
fi
$IP6TABLES -A rmt_tcp_client_request -p tcp --dport ssh \
		-j ACCEPT
$IP6TABLES -A lcl_tcp_srv_response -p tcp  ! --syn --sport ssh \
		-j ACCEPT


#########################################################################################
# Firewall and LAN UDP clients to remote UDP servers for those remote services that both
# the firewall and the LAN machines should be able to use. There will also likely
# be services (e.g., the DNS service above) that the firewall has access to that the
# LAN machines do not. There is also a separate set for TCP servers.
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)F/W & LAN UDP clts->Internet: "
fi

#####################
# Set up the chains #
#####################
# A UDP client on the firewall talking to remote server
$IP6TABLES -A ext_if_out -p udp -j local_udp_client_request
$IP6TABLES -A ext_if_in -p udp -j remote_udp_srv_response
# A UDP client on the LAN talking to a remote server
$IP6TABLES -A int_ext -p udp -j local_udp_client_request
$IP6TABLES -A ext_int -p udp -j remote_udp_srv_response

####################
# Set up the rules #
####################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "NTP, "
fi

# NTP time client - Current rule allows LAN and firewall to talk to any NTP Server.
# There are $TIME_SERVER1 - $TIMESERVER6 variables available to tighten this up if
# necessary.
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A local_udp_client_request -p udp --sport ntp --dport ntp \
             -m state --state NEW \
             -j ACCEPT
fi
$IP6TABLES -A local_udp_client_request -p udp --sport $UNPRIVPORTS --dport ntp \
         -j ACCEPT
$IP6TABLES -A remote_udp_srv_response -p udp --sport ntp --dport $UNPRIVPORTS \
         -j ACCEPT

# SNMP - Current rule allows LAN and firewall to SNMP with any IP addr.
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "SNMP, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A local_udp_client_request -p udp --sport $UNPRIVPORTS \
    	--dport snmp:snmptrap -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A local_udp_client_request -p udp --sport $UNPRIVPORTS \
	--dport snmp:snmptrap \
        -j ACCEPT
$IP6TABLES -A remote_udp_srv_response -p udp --sport snmp:snmptrap \
         --dport $UNPRIVPORTS -j ACCEPT

# HTTPS - used by virtually every website today
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "https, "
fi
$IP6TABLES -A local_udp_client_request -p udp --sport $UNPRIVPORTS --destination-port https \
        -j ACCEPT

# Traceroute - Current rule allows LAN and firewall to traceroute to any IP addr.
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "traceroute, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A local_udp_client_request -p udp --sport $TRACEROUTE_SRC_PORTS \
    	--dport $TRACEROUTE_DEST_PORTS -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A local_udp_client_request -p udp --sport $TRACEROUTE_SRC_PORTS \
	--dport $TRACEROUTE_DEST_PORTS \
        -j ACCEPT
$IP6TABLES -A remote_udp_srv_response -p udp --sport $TRACEROUTE_DEST_PORTS \
         --dport $TRACEROUTE_SRC_PORTS -j ACCEPT

# Multicast DNS
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)  & Mutlicast DNS "
fi
$IP6TABLES -A local_udp_client_request -p udp --dport $MULTICAST_DNS_UDP_PORT \
         -j ACCEPT
$IP6TABLES -A remote_udp_srv_response -p udp --sport $MULTICAST_DNS_UDP_PORT \
         -j ACCEPT


#########################################################################################
# The firewall machine originating UDP requests to the Internal LAN UDP machines.
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)UDP F/W - Local Lan: "
fi

#####################
# Set up the chains #
#####################
$IP6TABLES -A lan_if_out -p udp -j LAN_udp_firewall_request
$IP6TABLES -A lan_if_in -p udp -j LAN_udp_firewall_response

####################
# Set up the rules #
####################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)CUPS printer ctrl "
fi
# Printer, Scanner, Copier, Fax
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A LAN_udp_firewall_request -p udp -s $LAN_IP --sport $UNPRIVPORTS \
    	-d $PRINTER --dport $PRINTER_CTRL_PORT1 -m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A LAN_udp_firewall_request -p udp -s $LAN_IP --sport $UNPRIVPORTS -d $PRINTER \
	--dport $PRINTER_CTRL_PORT1 -j ACCEPT
$IP6TABLES -A LAN_udp_firewall_response -p udp -s $PRINTER --sport $PRINTER_CTRL_PORT1 \
	-d $LAN_IP --dport $UNPRIVPORTS -j ACCEPT
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A LAN_udp_firewall_request -p udp --sport $UNPRIVPORTS -d $PRINTER --dport $PRINTER_CTRL_PORT2 \
             -m state --state NEW \
             -j ACCEPT
fi
$IP6TABLES -A LAN_udp_firewall_request -p udp --sport $UNPRIVPORTS -d $PRINTER \
	--dport $PRINTER_CTRL_PORT2 -j ACCEPT
$IP6TABLES -A LAN_udp_firewall_response -p udp -s $PRINTER --sport $PRINTER_CTRL_PORT2 \
	--dport $UNPRIVPORTS -j ACCEPT


#########################################################################################
# The firewall machine originating TCP requests to the Internal LAN UDP machines.
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)TCP F/W - Local Lan: "
fi
#####################
# Set up the chains #
#####################
$IP6TABLES -A lan_if_out -p tcp -j LAN_tcp_firewall_request
$IP6TABLES -A lan_if_in -p tcp -j LAN_tcp_firewall_response

####################
# Set up the rules #
####################
# Printer, Scanner, Copier, Fax
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)CUPS printer ctrl "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A LAN_tcp_firewall_request -p tcp -s $LAN_IP --sport $UNPRIVPORTS \
    	-d $PRINTER --dport $PRINTER_TCP_PRINTING -m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A LAN_tcp_firewall_request -p tcp -s $LAN_IP --sport $UNPRIVPORTS -d $PRINTER \
	--dport $PRINTER_TCP_PRINTING -j ACCEPT
$IP6TABLES -A LAN_tcp_firewall_response -p tcp -s $PRINTER --sport $PRINTER_TCP_PRINTING \
	-d $LAN_IP --dport $UNPRIVPORTS -j ACCEPT


#########################################################################################
# A remote (potentially) untrusted internet client talking to a Local UDP server.
# There is also a separate set for TCP servers.
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)UDP F/W - Internet: "
fi

#####################
# Set up the chains #
#####################
$IP6TABLES -A ext_if_in -p udp --sport $UNPRIVPORTS -j remote_udp_client_request
$IP6TABLES -A ext_if_out -p udp --dport $UNPRIVPORTS -j local_udp_srv_response

####################
# Set up the rules #
####################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6) traceroute."
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A remote_udp_client_request -p udp --sport $TRACEROUTE_SRC_PORTS \
        --dport $TRACEROUTE_DEST_PORTS -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A remote_udp_client_request -p udp --sport $TRACEROUTE_SRC_PORTS \
        --dport $TRACEROUTE_DEST_PORTS \
        -j ACCEPT
$IP6TABLES -A local_udp_srv_response -p udp --sport $TRACEROUTE_DEST_PORTS \
         --dport $TRACEROUTE_SRC_PORTS -j ACCEPT


#########################################################################################
# Global IP ICMP requests to and from the firewall machine from the Internet
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)ICMP F/W-WAN (Global IP): "
fi

#####################
# Set up the chains #
#####################
$IP6TABLES -A ext_if_in -p icmpv6 -j ext_if_icmp_in
$IP6TABLES -A ext_if_out -p icmpv6 -j ext_if_icmp_out

####################
# Set up the rules #
####################

# Link local neighbor solicitation (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "link local neighbor solicitation (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_icmp_out -p icmpv6 --icmpv6-type neighbor-solicitation \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A ext_if_icmp_out -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT

# Link local neighbor solicitation (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "link local neighbor solicitation (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_icmp_in -p icmpv6 --icmpv6-type neighbor-solicitation \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A ext_if_icmp_in -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT

# Neighbor advertisement (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) neighbor advertisement (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_icmp_in -p icmpv6 --icmpv6-type neighbor-advertisement \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A ext_if_icmp_in -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

# Neighbor advertisement (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "neighbor advertisement (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_icmp_out -p icmpv6 --icmpv6-type neighbor-advertisement \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A ext_if_icmp_out -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

# Outgoing ping and incoming reply
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6) ping (out), reply (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_icmp_out -p icmpv6 --icmpv6-type echo-request \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_icmp_out -p icmpv6 --icmpv6-type echo-request -j ACCEPT
$IP6TABLES -A ext_if_icmp_in -p icmpv6 --icmpv6-type echo-reply -j ACCEPT

# Incoming ping
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ping (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_icmp_in -p icmpv6 -s $INTERNET_IP --icmpv6-type echo-request \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_icmp_in -p icmpv6 --icmpv6-type echo-request -s $INTERNET_IP \
	-j ACCEPT
$IP6TABLES -A ext_if_icmp_out -p icmpv6 --icmpv6-type echo-reply -d $INTERNET_IP \
	-j ACCEPT

# Destination Unreachable Type 3 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "dest unreachable, "
fi
$IP6TABLES -A ext_if_icmp_in -p icmpv6 --icmpv6-type destination-unreachable -j ACCEPT

# Parameter Problem 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "parm problem, "
fi
$IP6TABLES -A ext_if_icmp_out -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT
$IP6TABLES -A ext_if_icmp_in -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT

# Time Exceeded
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& time exceeded, "
fi
$IP6TABLES -A ext_if_icmp_in -p icmpv6 --icmpv6-type time-exceeded -j ACCEPT


#########################################################################################
# ICMP requests to and from the internal LAN to both the internal interface and the
# external interface. (We treat requests from the internal machines the same way 
# regardless of which interface they hit.)
# (In IPv4, some LAN services tried to talk to the external interface [notably DNS
# requests] so we had to allow for that. In IPv6, that should not happen. We have chains
# reserved [ext_if_lan_in and ext_if_lan_out] in case it does, but we're starting with
# those empty.)
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)ICMP F/W-LAN (LAN IP): "
fi

#####################
# Set up the chains #
#####################
$IP6TABLES -A lan_if_in -p icmpv6 -j lan_if_icmp_in
$IP6TABLES -A ext_if_lan_in -p icmpv6 -j lan_if_icmp_in
$IP6TABLES -A lan_if_out -p icmpv6 -j lan_if_icmp_out
$IP6TABLES -A ext_if_lan_out -p icmpv6 -j lan_if_icmp_out

####################
# Set up the rules #
####################

# Link local to multicast neighbor advetisement (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) neighbor advertisement (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_icmp_in -p icmpv6 --icmpv6-type neighbor-advertisement \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_icmp_in -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

# Link local to multicast neighbor advertisement (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "neighbor advertisement (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_icmp_out -p icmpv6 --icmpv6-type neighbor-advertisement \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_icmp_out -p icmpv6 --icmpv6-type neighbor-advertisement -j ACCEPT

# Link local to multicast neighbor solicitation (incoming)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "(IPv6) neighbor solicitation (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_icmp_in -p icmpv6 --icmpv6-type neighbor-solicitation \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_icmp_in -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT

# Link local to multicast neighbor solicitation (outgoing)
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "neighbor solicitation (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_icmp_out -p icmpv6 --icmpv6-type neighbor-solicitation \
        -m state --state NEW \
        -j ACCEPT
fi
$IP6TABLES -A lan_if_icmp_out -p icmpv6 --icmpv6-type neighbor-solicitation -j ACCEPT

# Outgoing ping and incoming reply
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6) ping (out), reply (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_icmp_out -p icmpv6 --icmpv6-type echo-request \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lan_if_icmp_out -p icmpv6 --icmpv6-type echo-request -j ACCEPT
$IP6TABLES -A lan_if_icmp_in -p icmpv6 --icmpv6-type echo-reply -j ACCEPT

# Incoming ping
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ping (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A lan_if_icmp_in -p icmpv6 -s $LAN_SUBNET --icmpv6-type echo-request \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A lan_if_icmp_in -p icmpv6 --icmpv6-type echo-request -s $LAN_SUBNET \
	-j ACCEPT
$IP6TABLES -A lan_if_icmp_out -p icmpv6 --icmpv6-type echo-reply -d $LAN_SUBNET \
	-j ACCEPT

# Destination Unreachable Type 3 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "dest unreachable, "
fi
$IP6TABLES -A lan_if_icmp_in -p icmpv6 --icmpv6-type destination-unreachable -j ACCEPT

# Parameter Problem 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "parm problem, "
fi
$IP6TABLES -A lan_if_icmp_out -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT
$IP6TABLES -A lan_if_icmp_in -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT

# Time Exceeded
if [ "$RUN_SILENTLY" != "1" ]; then
	echo  "& time exceeded, "
fi
$IP6TABLES -A lan_if_icmp_in -p icmpv6 --icmpv6-type time-exceeded -j ACCEPT


#########################################################################################
# ICMP requests to and from the internal LAN to destinations on the Internet. Although
# we have no objections to LAN machines pinging remote hosts, we don't allow the
# reverse to occur
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)ICMP LAN-WAN (Global IP): "
fi

#####################
# Set up the chains #
#####################
$IP6TABLES -A ext_int -p icmpv6 -j ext_int_icmp
$IP6TABLES -A int_ext -p icmpv6 -j int_ext_icmp

####################
# Set up the rules #
####################

# Router solicitation
# if [ "$RUN_SILENTLY" != "1" ]; then
#         echo -n "router solicitation (in), "
# fi
# if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
#     $IP6TABLES -A int_ext_icmp -s $LINK_LOCAL -d $MULTICAST -p icmpv6 --icmpv6-type router-solicitation \
# 	-m state --state NEW \
# 	-j ACCEPT
# fi
# $IP6TABLES -A int_ext_icmp -s $LINK_LOCAL -d $MULTICAST -p icmpv6 --icmpv6-type router-solicitation -j ACCEPT

# Router advertisement
# if [ "$RUN_SILENTLY" != "1" ]; then
#         echo -n "router advertisement (out), "
# fi
# if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
#     $IP6TABLES -A ext_int_icmp -s $LINK_LOCAL -d $MULTICAST -p icmpv6 --icmpv6-type router-advertisement \
# 	-m state --state NEW \
# 	-j ACCEPT
# fi
# $IP6TABLES -A ext_int_icmp -s $LINK_LOCAL -d $MULTICAST -p icmpv6 --icmpv6-type router-advertisement -j ACCEPT


# Outgoing ping & incoming reply
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ping (out), reply (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A int_ext_icmp -p icmpv6 --icmpv6-type echo-request \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A int_ext_icmp -p icmpv6 --icmpv6-type echo-request -j ACCEPT
$IP6TABLES -A ext_int_icmp -p icmpv6 --icmpv6-type echo-reply -j ACCEPT

# Incoming ping
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "ping (in-any), reply (out) "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_int_icmp -p icmpv6 --icmpv6-type echo-request \
	-m state --state NEW -j ACCEPT
fi
$IP6TABLES -A ext_int_icmp -p icmpv6 --icmpv6-type echo-request -j ACCEPT
$IP6TABLES -A int_ext_icmp -p icmpv6 --icmpv6-type echo-reply -j ACCEPT


# Incoming ping
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "& ping (in-WAN) "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A ext_if_icmp_in -p icmpv6 -s $INTERNET_IP --icmpv6-type echo-request \
	-m state --state NEW \
	-j ACCEPT
fi
$IP6TABLES -A ext_if_icmp_in -p icmpv6 --icmpv6-type echo-request -s $INTERNET_IP \
        -j ACCEPT
$IP6TABLES -A ext_if_icmp_out -p icmpv6 --icmpv6-type echo-reply -d $INTERNET_IP \
        -j ACCEPT



#########################################################################################
#########################################################################################
# Specific rules for VPN and specific services for select LAN clients
#########################################################################################
#########################################################################################

if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Establishing services for VPN: "
fi

#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on VPN machine
$IP6TABLES -A int_ext -s $VPN_TUNNEL -j vpn_machine_out
$IP6TABLES -A ext_int -d $VPN_TUNNEL -j vpn_machine_in

####################
# Set up the rules #
####################
VPN_SERVICE_UDP_PORT="10000"
VPN_SERVICE2_UDP_PORT_RNG="1560:1579"
VPN_SERVICE2_UDP_PORT="4500"
VPN_SERVICE3_UDP_PORT="51294"
VPN_SERVICE3_UDP_PORT2="10500"
VPN_SERVICE3_UDP_PORT_RNG="3470:3489"
VPN_SERVICE_TCP_PORT="5007"
VPN_SERVICE_TCP_PORT_RNG="10000:10010"
VPN_SERVICE2_TCP_PORT="1567"
VPN_SERVICE3_TCP_PORT="8531"
VPN_SERVICE3_TCP_PORT2="8014"
VPN_SERVICE3_TCP_PORT3_RNG="9501:9502"
VPN_SERVICE3_TCP_PORT4="10123"
VPN_SERVICE3_TCP_PORT_RNG="5091:5092"
# These are all placeholders until we have a real need for VPN on IPv6
# Obtained by executing:  dig us.all.vpn.airdns.org AAAA
VPN_IP="2601:1000:2000:3000::4000"     			# VPN nework IP (work-dev)
VPN2_IP="2601:1000:2000:3000::0001:4000"        	# VPN nework IP (work-staging)
VPN3_IP="2601:1000:2000:3000::0002:4000"         	# VPN nework IP (work-prod)

# VPN service
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)VPN, "
fi
$IP6TABLES -A vpn_machine_out -p esp -j ACCEPT
$IP6TABLES -A vpn_machine_out -p udp --sport isakmp \
    --dport isakmp -j ACCEPT
$IP6TABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS  \
    --dport $VPN_SERVICE_TCP_PORT -j ACCEPT
$IP6TABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS  \
    --dport $VPN_SERVICE_TCP_PORT_RNG -j ACCEPT
$IP6TABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS  \
    --dport $VPN_SERVICE3_TCP_PORT_RNG -j ACCEPT
$IP6TABLES -A vpn_machine_out -p 47 -j ACCEPT
$IP6TABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS  \
    --dport $VPN_SERVICE2_UDP_PORT -j ACCEPT
$IP6TABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS  \
    --dport $VPN_SERVICE3_UDP_PORT2 -j ACCEPT
$IP6TABLES -A vpn_machine_out -p udp --sport $VPN_SERVICE3_UDP_PORT  \
    --dport $VPN_SERVICE3_UDP_PORT -j ACCEPT
$IP6TABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS  \
    --dport $VPN_SERVICE3_UDP_PORT_RNG -j ACCEPT
$IP6TABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS  \
    -d $VPN2_IP --dport isakmp -j ACCEPT
$IP6TABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS  \
    -d $VPN3_IP --dport isakmp -j ACCEPT
$IP6TABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS  \
    --dport domain -j ACCEPT
$IP6TABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS  \
    -d $VPN2_IP --dport $UNPRIVPORTS -j ACCEPT
$IP6TABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS  \
    -d $VPN3_IP --dport $UNPRIVPORTS -j ACCEPT
$IP6TABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS  \
    --dport isakmp -j ACCEPT
$IP6TABLES -A vpn_machine_out -p udp --sport $VPN_SERVICE_UDP_PORT  \
    --dport $VPN_SERVICE_UDP_PORT -j ACCEPT
$IP6TABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS \
    -d $VPN_IP --dport $UNPRIVPORTS -j ACCEPT
$IP6TABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS \
    -d $VPN2_IP --dport $UNPRIVPORTS -j ACCEPT
$IP6TABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS \
    -d $VPN3_IP --dport $VPN_SERVICE3_TCP_PORT -j ACCEPT
$IP6TABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS \
    --dport $VPN_SERVICE3_TCP_PORT2 -j ACCEPT
$IP6TABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS \
    --dport $VPN_SERVICE3_TCP_PORT3_RNG -j ACCEPT
$IP6TABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS \
    --dport $VPN_SERVICE3_TCP_PORT4 -j ACCEPT

$IP6TABLES -A vpn_machine_in -p esp -j ACCEPT
$IP6TABLES -A vpn_machine_in -p udp --sport isakmp \
    --dport isakmp -j ACCEPT
$IP6TABLES -A vpn_machine_in -p udp --sport $VPN_SERVICE_UDP_PORT \
    --dport $VPN_SERVICE_UDP_PORT -j ACCEPT

# mail via SSH tunnels
if [ "$RUN_SILENTLY" != "1" ]; then
	echo  "& mail tunnels "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    $IP6TABLES -A vpn_machine_out -p tcp --dport $VPN_CLIENT_MAIL_PORTS \
             -m state --state NEW \
             -j ACCEPT
fi
$IP6TABLES -A vpn_machine_out -p tcp --dport $VPN_CLIENT_MAIL_PORTS \
         -j ACCEPT
$IP6TABLES -A vpn_machine_in -p tcp  ! --syn --sport $VPN_CLIENT_MAIL_PORTS \
         -j ACCEPT


#########################################################################################
# Rules for guest gaming desktop
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Establishing rules for guest gaming desktop: "
fi
#####################
# Set up the chains #
#####################
# A TCP/UDP exchange 
$IP6TABLES -A int_ext -s $GUESTGAMER -j guest_gamer_out
$IP6TABLES -A ext_int -d $GUESTGAMER -j guest_gamer_in

####################
# Set up the rules #
####################

####################
# Guild Wars 2
####################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Guild Wars 2, "
fi
# Constants 
GW2_TCP_PORT1="6112"
GW2_TCP_PORT2="6600"
$IP6TABLES -A guest_gamer_out -p tcp --sport $GW2_TCP_PORT1 \
	--dport $UNPRIVPORTS \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p tcp --sport $GW2_TCP_PORT2 \
	--dport $UNPRIVPORTS \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS \
        --dport $GW2_TCP_PORT1 \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS \
        --dport $GW2_TCP_PORT2 \
	-j ACCEPT
$IP6TABLES -A guest_gamer_in -p tcp --sport $UNPRIVPORTS \
	--dport $GW2_TCP_PORT1 \
	-j ACCEPT
$IP6TABLES -A guest_gamer_in -p tcp --sport $UNPRIVPORTS \
	--dport $GW2_TCP_PORT2 \
	-j ACCEPT

IRC_TCP_PORT_RNG1="6660:6669"
IRC_TCP_PORT_RNG2="5000:5009"
$IP6TABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS \
	--dport $IRC_TCP_PORT_RNG1  \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS \
	--dport $IRC_TCP_PORT_RNG2  \
	-j ACCEPT

##############################
# League of Legends
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "LoL, "
fi

LOL_UDP_PORT1="8088"
LOL_UDP_PORT_RNG1="5000:5500"
LOL_TCP_PORT_RNG1="8393:8400"
LOL_TCP_PORT_LIST1="5222,5223,2099,8088"
$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \
	--dport $LOL_UDP_PORT_RNG1  \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS \
	--dport $LOL_TCP_PORT_RNG1  \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \
	--dport $LOL_UDP_PORT1  \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS \
	-m multiport --dports $LOL_TCP_PORT_LIST1 \
	-j ACCEPT

##############################
# Payday 2
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6) Payday 2, "
fi
# Limit of 15 ports in a multiport list 
PAYDAY2_UDP_PORT_LIST1="9899,27017,60071"
$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \
	-m multiport --dports $PAYDAY2_UDP_PORT_LIST1 \
	-j ACCEPT

##############################
# Roblox
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Roblox, "
fi

ROBLOX_UDP_PORT_RNG="49152:65535"
$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \
	--dport $ROBLOX_UDP_PORT_RNG  \
	-j ACCEPT

$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \

##############################
# Killing Floor
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Killing Floor (1-2) "
fi
KF_GAME_UDP_PORT="7707"
KF2_GAME_TCP_UDP_PORT="7777"
KF_QUERY_UDP_PORT="7708"
KF_WEBADMIN_TCP_PORT="8075"
KF2_WEBADMIN_TCP_PORT="8080"
GAMESPY_QUERY_UDP_PORT_RNG="7717:7718"
STEAM_UDP_PORT="20560"
KF_MASTER_SVR_TCP_PORT="28852"
KF_MASTER_SVR_UDP_PORT="28852"
KF2_MASTER_SVR_TCP_UDP_PORT="27015"
$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \
	--dport $KF_GAME_UDP_PORT \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \
	--dport $KF_QUERY_UDP_PORT \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \
	--dport $KF2_GAME_TCP_UDP_PORT \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS \
	--dport $KF2_GAME_TCP_UDP_PORT \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS \
	--dport $KF_WEBADMIN_TCP_PORT \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS \
	--dport $KF2_WEBADMIN_TCP_PORT \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \
	--dport $GAMESPY_QUERY_UDP_PORT_RNG \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_UDP_PORT \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \
	--dport $KF_MASTER_SVR_UDP_PORT \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS \
	--dport $KF_MASTER_SVR_TCP_PORT \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \
	--dport $KF2_MASTER_SVR_TCP_UDP_PORT \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS \
	--dport $KF2_MASTER_SVR_TCP_UDP_PORT \
	-j ACCEPT

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& Steam "
fi
STEAM_FRIENDS_UDP_PORT="1200"
STEAM_SVR_SEARCH_UDP_PORT2="1713"
STEAM_UDP_PORT_RNG="3000:4999"
STEAM_UDP_PORT_RNG2="58500:58999"
STEAM_UDP_PORT_RNG3="27000:27250"
STEAM_UDP_SRC_PORT="3443"
STEAM_TCP_PORT_RNG="27000:27250"
STEAM_TCP_CROSS_CONNECT_PORT="9000"
STEAM_DED_SVR_UDP_PORT1="27015"
STEAM_DED_SVR_UDP_PORT2="27020"
$IP6TABLES -A guest_gamer_out -p udp --sport $STEAM_SVR_SEARCH_UDP_PORT2 \
	--dport $UNPRIVPORTS \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_FRIENDS_UDP_PORT \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_UDP_PORT_RNG \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_UDP_PORT_RNG2 \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_UDP_PORT_RNG3 \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS \
	--dport $STEAM_TCP_PORT_RNG \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS \
	--dport $STEAM_TCP_CROSS_CONNECT_PORT \
	-j ACCEPT
$IP6TABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_DED_SVR_UDP_PORT1 \
	-j ACCEPT
$IP6TABLES -A guest_gamer_in -p udp --sport $STEAM_UDP_SRC_PORT \
	--dport $UNPRIVPORTS \
	-j ACCEPT
$IP6TABLES -A guest_gamer_in -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_DED_SVR_UDP_PORT1 \
	-j ACCEPT
$IP6TABLES -A guest_gamer_in -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_DED_SVR_UDP_PORT2 \
	-j ACCEPT

#########################################################################################
# Amazon and Kasa devices
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Establishing rules for Amazon and Kasa devices: "
fi
#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on Amazon and Kasa smart plugs and switches
$IP6TABLES -A int_ext -s $FRONTLIGHTS -j smartplugswitch_out
$IP6TABLES -A ext_int -d $FRONTLIGHTS -j smartplugswitch_in
## Note this is not a complete list, but we don't have rules for the switches and 
## plugs .. yet

####################
# Set up the rules #
####################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Default rules only."
fi


#########################################################################################
# Networked Printer
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "Establishing rules for networked printer: "
fi
#####################
# Set up the chains #
#####################
$IP6TABLES -A int_ext -s $PRINTER -j network_printer_out
$IP6TABLES -A ext_int -d $PRINTER -j network_printer_in

####################
# Set up the rules #
####################
if [ "$RUN_SILENTLY" != "1" ]; then
        echo "Manufacturer Support "
fi

$IP6TABLES -A network_printer_out -p tcp --sport $UNPRIVPORTS \
        --dport $GOOGLE_TALK_TCP_PORT  \
        -j ACCEPT


#########################################################################################
# Specific rules for laptops
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Establishing rules for Laptops: "
fi
#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on Laptops
$IP6TABLES -A int_ext -s $MYLAPTOP -j laptop_out
$IP6TABLES -A ext_int -d $MYLAPTOP -j laptop_in

####################
# Set up the rules #
####################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Hangouts, "
fi

#############################
# Google Hangouts port setup
#############################
HANGOUTS_TCP_UDP_PORT_RNG="19302:19309"
$IP6TABLES -A laptop_out -p udp --sport $UNPRIVPORTS \
	--dport $HANGOUTS_TCP_UDP_PORT_RNG  \
	-j ACCEPT
$IP6TABLES -A laptop_out -p tcp --sport $UNPRIVPORTS \
	--dport $HANGOUTS_TCP_UDP_PORT_RNG  \
	-j ACCEPT
$IP6TABLES -A laptop_out -p tcp --sport $UNPRIVPORTS \
	--dport $GOOGLE_PLAYSTORE_TCP_PORT  \
	-j ACCEPT

#############################
# Discord Audio Server
#############################
# if [ "$RUN_SILENTLY" != "1" ]; then
# 	echo -n "(IPv6)Discord audio, "
# fi

# DISCORD_AUDIO_SERVER="107.160.169.222"
# DISCORD_AUDIO_SERVER2="162.245.207.213"
# DISCORD_UDP_PORT_RNG="50001:65535"
# $IP6TABLES -A laptop_out -p udp --sport $UNPRIVPORTS \
# 	-d $DISCORD_AUDIO_SERVER --dport $DISCORD_UDP_PORT_RNG  \
# 	-j ACCEPT

# $IP6TABLES -A laptop_out -p udp --sport $UNPRIVPORTS \
# 	-d $DISCORD_AUDIO_SERVER2 --dport $DISCORD_UDP_PORT_RNG  \
# 	-j ACCEPT

#############################
# Oculus Cast
#############################
# if [ "$RUN_SILENTLY" != "1" ]; then
# 	echo -n "(IPv6)Oculus Cast, "
# fi

# OCULUS_CAST_SERVER1="31.13.66.52"
# OCULUS_CAST_SERVER2="157.240.229.59"
# OCULUS_CAST_UDP_PORT_RNG="40000:49999"
# $IP6TABLES -A laptop_out -p udp --sport $UNPRIVPORTS \
# 	-d $OCULUS_CAST_SERVER1 --dport $OCULUS_CAST_UDP_PORT_RNG  \
# 	-j ACCEPT

# $IP6TABLES -A laptop_out -p udp --sport $UNPRIVPORTS \
# 	-d $OCULUS_CAST_SERVER2 --dport $OCULUS_CAST_UDP_PORT_RNG  \
# 	-j ACCEPT

#############################
# IRC
#############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)IRC, "
fi

IRC_TCP_PORT_RNG1="6660:6669"
IRC_TCP_PORT_RNG2="5000:5009"
$IP6TABLES -A laptop_out -p tcp --sport $UNPRIVPORTS \
	--dport $IRC_TCP_PORT_RNG1  \
	-j ACCEPT
$IP6TABLES -A laptop_out -p tcp --sport $UNPRIVPORTS \
	--dport $IRC_TCP_PORT_RNG2  \
	-j ACCEPT

#############################
# Steam
#############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)& Steam "
fi
STEAM_FRIENDS_UDP_PORT="1200"
STEAM_SVR_SEARCH_UDP_PORT2="1713"
STEAM_UDP_PORT_RNG="3000:4999"
STEAM_UDP_PORT_RNG2="58500:58999"
STEAM_UDP_PORT_RNG3="27000:27050"
STEAM_UDP_SRC_PORT="3443"
STEAM_TCP_PORT_RNG="27000:27050"
STEAM_TCP_CROSS_CONNECT_PORT="9000"
STEAM_TCP_PORT_FRIENDS_LIST="44325"
STEAM_DED_SVR_UDP_PORT1="27015"
STEAM_DED_SVR_UDP_PORT2="27020"
$IP6TABLES -A laptop_out -p udp --sport $STEAM_SVR_SEARCH_UDP_PORT2 \
	--dport $UNPRIVPORTS \
	-j ACCEPT
$IP6TABLES -A laptop_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_FRIENDS_UDP_PORT \
	-j ACCEPT
$IP6TABLES -A laptop_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_UDP_PORT_RNG \
	-j ACCEPT
$IP6TABLES -A laptop_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_UDP_PORT_RNG2 \
	-j ACCEPT
$IP6TABLES -A laptop_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_UDP_PORT_RNG3 \
	-j ACCEPT
$IP6TABLES -A laptop_out -p tcp --sport $UNPRIVPORTS \
	--dport $STEAM_TCP_PORT_RNG \
	-j ACCEPT
$IP6TABLES -A laptop_out -p tcp --sport $UNPRIVPORTS \
	--dport $STEAM_TCP_PORT_FRIENDS_LIST \
	-j ACCEPT
$IP6TABLES -A laptop_out -p tcp --sport $UNPRIVPORTS \
	--dport $STEAM_TCP_CROSS_CONNECT_PORT \
	-j ACCEPT
$IP6TABLES -A laptop_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_DED_SVR_UDP_PORT1 \
	-j ACCEPT
$IP6TABLES -A laptop_in -p udp --sport $STEAM_UDP_SRC_PORT \
	--dport $UNPRIVPORTS \
	-j ACCEPT


#########################################################################################
# Android phones
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Establishing rules for Android phones: "
fi

#####################
# Set up the chains #
#####################
$IP6TABLES -A int_ext -s $SAMSUNG23U -j samsungphone_out
$IP6TABLES -A ext_int -d $SAMSUNG23U -j samsungphone_in
$IP6TABLES -A int_ext -s $SAMSUNGS24 -j samsungphone_out
$IP6TABLES -A ext_int -d $SAMSUNGS24 -j samsungphone_in

####################
# Set up the rules #
####################
#
# Deeptown: Mining server (See above for variable defs)
#
# if [ "$RUN_SILENTLY" != "1" ]; then
# 	echo -n "(IPv6)Deeptown, "
# fi
# $IP6TABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS \
# 	-d $DEEPTOWN_SERVER --dport $DEEPTOWN_TCP_PORT  \
# 	-j ACCEPT
#
# World of Warcraft Companion App
#
# BATTLE_NET_APP_SERVER="137.221.0.0/16"
# BATTLE_NET_APP_SERVER_TCP_PORT="1119"
# BATTLE_NET_APP_SERVER_TCP_PORT2="5222"
# WOW_COMPANION_APP_SERVER="24.105.28.10"
# WOW_COMPANION_APP_SERVER_TCP_PORT="1119"
# WOW_COMPANION_APP_SERVER2="24.105.0.151"
# WOW_COMPANION_APP_SERVER_TCP_PORT2="6012"
# WOW_COMPANION_APP_SERVER3="24.105.29.40"
# WOW_COMPANION_APP_SERVER_TCP_PORT3="8743"
# if [ "$RUN_SILENTLY" != "1" ]; then
# 	echo -n "(IPv6)Battle.net, WoW, Diablo IV, "
# fi
# $IP6TABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS \
# 	-d $BATTLE_NET_APP_SERVER --dport $BATTLE_NET_APP_SERVER_TCP_PORT  \
# 	-j ACCEPT
# $IP6TABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS \
# 	-d $BATTLE_NET_APP_SERVER --dport $BATTLE_NET_APP_SERVER_TCP_PORT2  \
# 	-j ACCEPT
# $IP6TABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS \
# 	-d $WOW_COMPANION_APP_SERVER --dport $WOW_COMPANION_APP_SERVER_TCP_PORT  \
# 	-j ACCEPT
# $IP6TABLES -A samsungphone_in -p tcp -s $WOW_COMPANION_APP_SERVER --sport $UNPRIVPORTS \
# 	--dport $UNPRIVPORTS \
# 	-j ACCEPT

# $IP6TABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS \
# 	-d $WOW_COMPANION_APP_SERVER2 --dport $WOW_COMPANION_APP_SERVER_TCP_PORT2  \
# 	-j ACCEPT
# $IP6TABLES -A samsungphone_in -p tcp -s $WOW_COMPANION_APP_SERVER2 --sport $UNPRIVPORTS \
# 	--dport $UNPRIVPORTS \
# 	-j ACCEPT

# $IP6TABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS \
# 	-d $WOW_COMPANION_APP_SERVER3 --dport $WOW_COMPANION_APP_SERVER_TCP_PORT3  \
# 	-j ACCEPT
# $IP6TABLES -A samsungphone_in -p tcp -s $WOW_COMPANION_APP_SERVER3 --sport $UNPRIVPORTS \
# 	--dport $UNPRIVPORTS \
# 	-j ACCEPT

# Roblox accessed from my cell phones
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Roblox, "
fi
ROBLOX_UDP_PORT="8092"
ROBLOX_UDP_PORT_RANGE="49152:65535"
$IP6TABLES -A samsungphone_out -p udp --sport $UNPRIVPORTS \
	--dport $ROBLOX_UDP_PORT  \
	-j ACCEPT
$IP6TABLES -A samsungphone_out -p udp --sport $UNPRIVPORTS \
	--dport $ROBLOX_UDP_PORT_RANGE  \
	-j ACCEPT

# Philips GroveTime Shaver app accessed from my cell phones
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Philips Shaver, "
fi
PHILIPS_UDP_PORT="19302"
$IP6TABLES -A samsungphone_out -p udp --sport $UNPRIVPORTS \
	--dport $PHILIPS_UDP_PORT  \
	-j ACCEPT

# DNS over TLS from my cell phones
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "DNS over TLS, "
fi
$IP6TABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS \
	--dport domain-s  \
	-j ACCEPT

# Google services accessed from my cell phones
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& Google Playstore, "
fi
$IP6TABLES -A samsungphone_out -p tcp  --sport $UNPRIVPORTS \
	--dport $GOOGLE_PLAYSTORE_TCP_PORT  \
	-j ACCEPT
$IP6TABLES -A samsungphone_out -p tcp  --sport $UNPRIVPORTS \
	--dport $GOOGLE_PLAYSTORE_TCP_PORT  \
	-j ACCEPT


#########################################################################################
# Samsung Galaxy Android Tablet
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Establishing rules for Android Tablets: "
fi
#####################
# Set up the chains #
#####################
$IP6TABLES -A int_ext -s $GALAXYTAB -j galaxytablet_out
$IP6TABLES -A ext_int -d $GALAXYTAB -j galaxytablet_in

####################
# Set up the rules #
####################
#
# Google Play Services
#
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Google Play, Roblox, Zooba, Among Us, Head Ball, Peppa Pig, "
fi

# Google Play port setup
TA_GOOGLE_PLAY_TCP_PORT_RNG1="22990:22999"
TA_GOOGLE_PLAY_TCP_PORT1="7275"
TA_GOOGLE_PLAY_TCP_UDP_PORT1="5228"
TA_GOOGLE_PLAY_TCP_UDP_PORT_RNG="3000:3009"
TA_GOOGLE_PLAY_TCP_UDP_PORT_RNG2="5228:5230"
TA_GOOGLE_PLAY_PURCHASING_TCP_PORT="30303"
TA_GOOGLE_PLAY_TEAM_CHAT_TCP_PORT="31313"
TA_AGAR_TCP_PORT1="9000"
KING_OF_THIEVES_TCP_PORT1="8001"
DRIVE_AHEAD_TCP_PORT1="9339"
DRAGON_GAME_TCP_PORT1="3051"
DRAGON_GAME_TCP_PORT2="8883"
DRAGON_GAME_TCP_PORT3="5001"
DRAGON_GAME_TCP_PORT4="22114"
DRAGON_GAME_UDP_PORT_RNG1="6000:7999"
AMONG_US_UDP_PORT_RNG1="45000:49999"
AMONG_US_UDP_PORT_RNG2="5000:5100"
AMONG_US_UDP_PORT_RNG3="8100:8199"
AMONG_US_UDP_PORT_RNG4="8440:8449"
JACK_GAME_TCP_PORT1="8060"
DEVIL_AMONG_US_TCP_PORT1="9933"
HEAD_BALL_UDP_PORT1="1433"
PEPPA_PIG_TCP_PORT1="9377"

$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $JACK_GAME_TCP_PORT1  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $TA_GOOGLE_PLAY_TCP_PORT_RNG1  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $TA_GOOGLE_PLAY_TCP_PORT1  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS \
	--dport $TA_GOOGLE_PLAY_TCP_UDP_PORT1  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS \
	--dport $TA_GOOGLE_PLAY_TCP_UDP_PORT_RNG  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $TA_GOOGLE_PLAY_TCP_UDP_PORT_RNG  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS \
	--dport $TA_GOOGLE_PLAY_TCP_UDP_PORT_RNG2  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $TA_GOOGLE_PLAY_TCP_UDP_PORT_RNG2  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $TA_GOOGLE_PLAY_PURCHASING_TCP_PORT  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $TA_GOOGLE_PLAY_TEAM_CHAT_TCP_PORT  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $TA_AGAR_TCP_PORT1  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS \
	--dport $ROBLOX_UDP_PORT  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS \
	--dport $ROBLOX_UDP_PORT_RANGE  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $KING_OF_THIEVES_TCP_PORT1  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $DRIVE_AHEAD_TCP_PORT1  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $DRAGON_GAME_TCP_PORT1  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $DRAGON_GAME_TCP_PORT2  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $DRAGON_GAME_TCP_PORT3  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $DRAGON_GAME_TCP_PORT4  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS \
	--dport $DRAGON_GAME_UDP_PORT_RNG1  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS \
	--dport $AMONG_US_UDP_PORT_RNG1  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS \
	--dport $AMONG_US_UDP_PORT_RNG2  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS \
	--dport $AMONG_US_UDP_PORT_RNG3  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS \
	--dport $AMONG_US_UDP_PORT_RNG4  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $DEVIL_AMONG_US_TCP_PORT1  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS \
	--dport $HEAD_BALL_UDP_PORT1  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $PEPPA_PIG_TCP_PORT1  \
	-j ACCEPT
FB_MESSENGER_KIDS_TCP_PORT1="3478"
FB_MESSENGER_KIDS_UDP_PORT_RNG1="40000:40009"
FB_MESSENGER_KIDS_UDP_PORT_RNG2="41400:41409"
$IP6TABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS \
	--dport $FB_MESSENGER_KIDS_UDP_PORT_RNG1  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS \
	--dport $FB_MESSENGER_KIDS_UDP_PORT_RNG2  \
	-j ACCEPT
$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	--dport $FB_MESSENGER_KIDS_TCP_PORT1  \
	-j ACCEPT

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6) and Minecraft "
fi

MINECRAFT_TCP_PORT_1="6667"
MINECRAFT_TCP_PORT_2="12400"
MINECRAFT_TCP_PORT_3="28910"
MINECRAFT_TCP_PORT_4="29900"
MINECRAFT_TCP_PORT_5="29901"
MINECRAFT_TCP_PORT_6="29920"
MINECRAFT_UDP_PORT_RNG1="19000:19999"

$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	 --dport $MINECRAFT_TCP_PORT_1 \
	 -j ACCEPT

$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	 --dport $MINECRAFT_TCP_PORT_2 \
	 -j ACCEPT

$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	 --dport $MINECRAFT_TCP_PORT_3 \
	 -j ACCEPT

$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	 --dport $MINECRAFT_TCP_PORT_4 \
	 -j ACCEPT

$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	 --dport $MINECRAFT_TCP_PORT_5 \
	 -j ACCEPT

$IP6TABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS \
	 --dport $MINECRAFT_TCP_PORT_6 \
	 -j ACCEPT

$IP6TABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS \
	 --dport $MINECRAFT_UDP_PORT_RNG1 \
	 -j ACCEPT


#########################################################################################
# Netgear Orbi's and TP-Link AX55 (as a WAP) specific rules
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Establishing rules for Orbi Base/Satellite and TP-Link AX55: "
fi
#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on the WAP
$IP6TABLES -A int_ext -s $ORBI -j wap_out
$IP6TABLES -A ext_int -d $ORBI -j wap_in
$IP6TABLES -A int_ext -s $ORBISATELLITE -j wap_out
$IP6TABLES -A ext_int -d $ORBISATELLITE -j wap_in
####################
# Set up the rules #
####################
# NTP server
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "daytime, "
fi
$IP6TABLES -A wap_out -p tcp --sport $UNPRIVPORTS \
	--dport daytime  \
	-j ACCEPT
$IP6TABLES -A wap_in -p tcp --sport daytime \
	--dport $UNPRIVPORTS \
	-j ACCEPT

# Update server
ORBI_UPDATE_SVC_PORT="8883"

if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "update svc, "
fi
$IP6TABLES -A wap_out -p tcp --sport $UNPRIVPORTS \
	--dport $ORBI_UPDATE_SVC_PORT  \
	-j ACCEPT

# DNS server
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& domain "
fi

$IP6TABLES -A wap_out -p tcp --sport $UNPRIVPORTS \
	--dport domain -j ACCEPT
$IP6TABLES -A wap_out -p tcp --sport $UNPRIVPORTS \
	--dport domain-s -j ACCEPT


#########################################################################################
# File Server
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Establishing rules for the File Server: "
fi

#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on the file server
$IP6TABLES -A int_ext -s $FILESERVER -j file_server_out
$IP6TABLES -A ext_int -d $FILESERVER -j file_server_in

####################
# Set up the rules #
####################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Default rules only. "
fi


#########################################################################################
# Specific rules for Roku 
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Establishing rules for Roku: "
fi

#####################
# Set up the chains #
#####################
$IP6TABLES -A int_ext -s $ROKU -j roku_out
$IP6TABLES -A ext_int -d $ROKU -j roku_in

####################
# Set up the rules #
####################
ROKU_UDP_PORT1="53"
ROKU_UDP_PORT2="853"
ROKU_TCP_PORT1="2350"
ROKU_GOOGLE_DNS_1=$NAMESERVER_1
ROKU_GOOGLE_DNS_2=$NAMESERVER_2

if [ "$RUN_SILENTLY" != "1" ]; then
 echo "(IPv6)Roku ports "
fi
 $IP6TABLES -A roku_out -p udp --sport $UNPRIVPORTS \
	 --dport $ROKU_UDP_PORT1 \
	 -j ACCEPT
$IP6TABLES -A roku_out -p udp --sport $UNPRIVPORTS \
	 --dport $ROKU_UDP_PORT2 \
	 -j ACCEPT
$IP6TABLES -A roku_out -p tcp --sport $UNPRIVPORTS \
	 --dport $ROKU_TCP_PORT1 \
	 -j ACCEPT
$IP6TABLES -A roku_out -p tcp --sport $UNPRIVPORTS \
	 -d $ROKU_GOOGLE_DNS_1 --dport domain \
	 -j ACCEPT
$IP6TABLES -A roku_out -p tcp --sport $UNPRIVPORTS \
	 -d $ROKU_GOOGLE_DNS_2 --dport domain \
	 -j ACCEPT
$IP6TABLES -A roku_out -p tcp --sport $UNPRIVPORTS \
	 -d $ROKU_GOOGLE_DNS_1 --dport domain-s \
	 -j ACCEPT
$IP6TABLES -A roku_out -p tcp --sport $UNPRIVPORTS \
	 -d $ROKU_GOOGLE_DNS_2 --dport domain-s \
	 -j ACCEPT


#########################################################################################
# Nintendo Switch
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Establishing rules for Nintendo Switch: "
fi

#####################
# Set up the chains #
#####################
$IP6TABLES -A int_ext -s $NINTENDOSWITCH -j switch_out
$IP6TABLES -A ext_int -d $NINTENDOSWITCH -j switch_in
 
####################
# Set up the rules #
####################

# Nintendo servers incoming (multiplayer, et. al)
SWITCH_UDP_PORT_FWD_RNG1="45000:65535"
SWITCH_TCP_PORT_FWD_1="25565"

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)and Minecraft "
fi

$IP6TABLES -A switch_out -p tcp --sport $UNPRIVPORTS \
	 --dport $MINECRAFT_TCP_PORT_1 \
	 -j ACCEPT

$IP6TABLES -A switch_out -p tcp --sport $UNPRIVPORTS \
	 --dport $MINECRAFT_TCP_PORT_2 \
	 -j ACCEPT

$IP6TABLES -A switch_out -p tcp --sport $UNPRIVPORTS \
	 --dport $MINECRAFT_TCP_PORT_3 \
	 -j ACCEPT

$IP6TABLES -A switch_out -p tcp --sport $UNPRIVPORTS \
	 --dport $MINECRAFT_TCP_PORT_4 \
	 -j ACCEPT

$IP6TABLES -A switch_out -p tcp --sport $UNPRIVPORTS \
	 --dport $MINECRAFT_TCP_PORT_5 \
	 -j ACCEPT

$IP6TABLES -A switch_out -p tcp --sport $UNPRIVPORTS \
	 --dport $MINECRAFT_TCP_PORT_6 \
	 -j ACCEPT

$IP6TABLES -A switch_out -p udp --sport $UNPRIVPORTS \
	 --dport $UNPRIVPORTS \
	 -j ACCEPT


#########################################################################################
# Specific rules for Ecobee 3 
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Establishing rules for Ecobee 3: "
fi

#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on the ecobee 3 thermostat
$IP6TABLES -A int_ext -s $ECOBEE3 -j ecobee3_out
$IP6TABLES -A ext_int -d $ECOBEE3 -j ecobee3_in

####################
# Set up the rules #
####################
ECOBEE3_TCP_PORT1="8089"
ECOBEE3_TCP_PORT_RNG1="8180:8199"

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Ecobee3 server ports "
fi

$IP6TABLES -A ecobee3_out -p tcp --sport $UNPRIVPORTS \
	--dport $ECOBEE3_TCP_PORT1 \
	-j ACCEPT

$IP6TABLES -A ecobee3_out -p tcp --sport $UNPRIVPORTS \
	--dport $ECOBEE3_TCP_PORT_RNG1 \
	-j ACCEPT


#########################################################################################
# Specific rules for the Steam Deck
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Establishing rules for Steam Deck: "
fi

#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on a SteamDeck
$IP6TABLES -A int_ext -s $STEAMDECK_WL -j steamdeck_out
$IP6TABLES -A ext_int -d $STEAMDECK_WL -j steamdeck_in
$IP6TABLES -A int_ext -s $STEAMDECK_DOCK -j steamdeck_out
$IP6TABLES -A ext_int -d $STEAMDECK_DOCK -j steamdeck_in

####################
# Set up the rules #
####################

# Steam
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Steam, "
fi
STEAM_FRIENDS_UDP_PORT="1200"
STEAM_SVR_SEARCH_UDP_PORT2="1713"
STEAM_UDP_PORT_RNG="3000:4999"
STEAM_UDP_PORT_RNG2="58500:58999"
STEAM_UDP_PORT_RNG3="27000:27050"
STEAM_UDP_SRC_PORT="3443"
STEAM_TCP_PORT_RNG="27000:27050"
STEAM_DED_SVR_UDP_RNG="27000:27050"
STEAM_DED_SVR_UDP_PORT1="27015"
STEAM_DED_SVR_UDP_PORT2="27020"
$IP6TABLES -A steamdeck_out -p udp --sport $STEAM_SVR_SEARCH_UDP_PORT2 \
	--dport $UNPRIVPORTS \
	-j ACCEPT
$IP6TABLES -A steamdeck_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_FRIENDS_UDP_PORT \
	-j ACCEPT
$IP6TABLES -A steamdeck_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_UDP_PORT_RNG \
	-j ACCEPT
$IP6TABLES -A steamdeck_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_UDP_PORT_RNG2 \
	-j ACCEPT
$IP6TABLES -A steamdeck_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_UDP_PORT_RNG3 \
	-j ACCEPT
$IP6TABLES -A steamdeck_out -p tcp --sport $UNPRIVPORTS \
	--dport $STEAM_TCP_PORT_RNG \
	-j ACCEPT
$IP6TABLES -A steamdeck_out -p tcp --sport $UNPRIVPORTS \
	--dport $STEAM_TCP_PORT_FRIENDS_LIST \
	-j ACCEPT
$IP6TABLES -A steamdeck_in -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_DED_SVR_UDP_RNG \
	-j ACCEPT
$IP6TABLES -A steamdeck_in -p udp --sport $STEAM_UDP_SRC_PORT \
	--dport $UNPRIVPORTS \
	-j ACCEPT


#########################################################################################
# Gaming PC specific rules for games and game servers
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Establishing rules for Gaming PC: "
fi
#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on gaming PC
$IP6TABLES -A int_ext -s $GAMINGPC -j gaming_pc_out
$IP6TABLES -A ext_int -d $GAMINGPC -j gaming_pc_in


####################
# Set up the rules #
####################


##############################
# Epic Games Launcher
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Epic Launcher, "
fi
# Constants 
EL_TCP_PORT1="5222"
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $EL_TCP_PORT1 \
	-j ACCEPT

##############################
# VNC
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "VNC (client), "
fi
# Constants 
VNC_TCP_PORT_RANGE="5900:5909"
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $VNC_TCP_PORT_RANGE \
	-j ACCEPT

##############################
# Mass Effect (1)
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Mass Effect, "
fi
# Constants 
ME_TCP_PORT1="5290"
ME_TCP_PORT2="42100"
ME_TCP_PORT_RANGE_1="15200:15300"
ME_TCP_PORT_RANGE_2="9945:9994"
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $ME_TCP_PORT1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $ME_TCP_PORT2 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $ME_TCP_PORT_RANGE_1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $ME_TCP_PORT_RANGE_2 \
	-j ACCEPT

##############################
# Mass Effect 2
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6) Mass Effect 2, "
fi
# Constants 
ME2_TCP_PORT1="2967"
ME2_TCP_PORT2="42100"
ME2_TCP_PORT_RANGE_1="15200:15300"
ME2_TCP_PORT_RANGE_2="9945:9994"
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $ME2_TCP_PORT1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $ME2_TCP_PORT2 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $ME2_TCP_PORT_RANGE_1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $ME2_TCP_PORT_RANGE_2 \
	-j ACCEPT

##############################
# Mass Effect 3
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Mass Effect 3, "
fi
# Constants 
ME3_TCP_PORT1="3658"
ME3_TCP_PORT2="42127"
ME3_TCP_PORT_RANGE_1="14200:14500"
ME3_TCP_PORT_RANGE_2="17400:17599"
ME3_UDP_PORT_RANGE_1="17400:17599"
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $ME3_TCP_PORT1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $ME3_TCP_PORT2 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $ME3_TCP_PORT_RANGE_1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $ME3_TCP_PORT_RANGE_2 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS \
	--dport $ME3_UDP_PORT_RANGE_1 \
	-j ACCEPT

##############################
# Mass Effect Andromeda
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Mass Effect Andromeda, "
fi
# Constants 
MEA_TCP_PORT1="17503"
MEA_TCP_PORT2="17504"
MEA_TCP_PORT3="42130"
MEA_TCP_PORT4="42210"
MEA_TCP_PORT4="42230"
MEA_TCP_PORT_RANGE_1="10000:10999"
MEA_UDP_PORT_RANGE_1="10000:10999"
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $MEA_TCP_PORT1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $MEA_TCP_PORT2 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $MEA_TCP_PORT3 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $MEA_TCP_PORT4 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $MEA_TCP_PORT_RANGE_1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS \
	--dport $MEA_UDP_PORT_RANGE_1 \
	-j ACCEPT


##############################
# Google Voice
##############################

if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "Google Voice, "
fi
$IP6TABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS \
        -d $GGOGLE_TALK_SERVER_RANGE --dport $GOOGLE_TALK_UDP_PORT_RNG \
        -j ACCEPT
$IP6TABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS \
        -d $GGOGLE_TALK_SERVER_RANGE --dport $GOOGLE_TALK_UDP_PORT_RNG2 \
        -j ACCEPT


###################
# World of Warcraft
###################
if [ "$RUN_SILENTLY" != "1" ]; then
 echo -n "WoW, "
fi
# Constants 
WOW_TCP_PORT_RNG1="6881:6999"
WOW_TCP_PORT_RNG2="4000:4249"
WOW_TCP_PORT1="3724"
WOW_TCP_PORT2="6112:6119"
WOW_TCP_PORT3="4000"
WOW_TCP_PORT4="1119"
WOW_TCP_CRASH_REPORT_PORT1="8086"
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
  	--dport $WOW_TCP_PORT_RNG1 \
 	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $WOW_TCP_PORT1 \
	--dport $UNPRIVPORTS \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $WOW_TCP_PORT1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $WOW_TCP_PORT2 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $WOW_TCP_PORT3 \
	--dport $UNPRIVPORTS \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $WOW_TCP_PORT4 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_in -p tcp --sport $UNPRIVPORTS \
	--dport $WOW_TCP_PORT1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_in -p udp --sport $UNPRIVPORTS \
	--dport $WOW_TCP_PORT1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $WOW_TCP_CRASH_REPORT_PORT1 \
	-j ACCEPT

###################
# Diablo IV
###################
if [ "$RUN_SILENTLY" != "1" ]; then
 echo -n "(IPv6) Diablo IV, "
fi

# Constants 
D4_SRC_TCP_PORT_RNG1="62000:62999"
D4_SERVER_TCP_PORT_RNG1="54540:54549"
D4_QUEUE_TCP_PORT_RNG1="28890:28899"

$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
  	--dport $D4_SERVER_TCP_PORT_RNG1 \
 	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
  	--dport $D4_QUEUE_TCP_PORT_RNG1 \
 	-j ACCEPT

###################
# Final Fantasy XIV
###################
if [ "$RUN_SILENTLY" != "1" ]; then
 echo -n "FFXIV, "
fi
# Constants 
FFXIV_TCP_PORT_RNG1="54992:54994"
FFXIV_TCP_PORT_RNG2="55006:55007"
FFXIV_TCP_PORT_RNG3="55021:55040"
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
  	--dport $FFXIV_TCP_PORT_RNG1 \
 	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $FFXIV_TCP_PORT_RNG2 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $FFXIV_TCP_PORT_RNG3 \
	-j ACCEPT

###################
# Lost Ark
###################
if [ "$RUN_SILENTLY" != "1" ]; then
 echo -n "Lost Ark, "
fi
# Constants 
LARK_TCP_PORT_RNG1="44330:44339"
LARK_TCP_PORT_RNG2="6000:6050"
LARK_TCP_PORT_RNG3="55021:55040"
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
  	--dport $LARK_TCP_PORT_RNG1 \
 	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $LARK_TCP_PORT_RNG2 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $LARK_TCP_PORT_RNG3 \
	-j ACCEPT

###################
# Guild Wars 2, Rift, Magic: Legends
###################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Guild Wars 2, Magic: Legends, "
fi
# Constants 
GW2_TCP_PORT1="6112"
GW2_TCP_PORT2="6600"
ML_TCP_PORT_RNG1="7000:7500"
RIFT_TCP_PORT_RNG1="6520:6540"
$IP6TABLES -A gaming_pc_out -p tcp --sport $GW2_TCP_PORT1 \
	--dport $UNPRIVPORTS \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $GW2_TCP_PORT2 \
	--dport $UNPRIVPORTS \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
        --dport $GW2_TCP_PORT2 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_in -p tcp --sport $UNPRIVPORTS \
	--dport $GW2_TCP_PORT1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_in -p tcp --sport $UNPRIVPORTS \
	--dport $GW2_TCP_PORT2 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
        --dport $RIFT_TCP_PORT_RNG1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
        --dport $ML_TCP_PORT_RNG1 \
	-j ACCEPT


##############################
# The First Descendant
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6) The First Descendant, "
fi
# Constants 
TFD_TCP_PORT1="27777"
TFD_TCP_PORT2="28909"
TFD_UDP_PORT_RNG1="17700:17999"
TFD_UDP_PORT1="52848"
$IP6TABLES -A gaming_pc_out -p tcp --dport $TFD_TCP_PORT1 \
        --sport $UNPRIVPORTS \
        -j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --dport $TFD_TCP_PORT2 \
        --sport $UNPRIVPORTS \
        -j ACCEPT
$IP6TABLES -A gaming_pc_out -p udp --dport $TFD_UDP_PORT_RNG1 \
        --sport $UNPRIVPORTS \
        -j ACCEPT
$IP6TABLES -A gaming_pc_out -p udp --dport $TFD_UDP_PORT1 \
        --sport $UNPRIVPORTS \
        -j ACCEPT


##############################
# Torchlight 2
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Torchlight 2, "
fi
# Constants 
TL2_TCP_PORT1="4549"
TL2_UDP_PORT2="59243"
$IP6TABLES -A gaming_pc_out -p tcp --dport $TL2_TCP_PORT1 \
	--sport $UNPRIVPORTS \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p udp --dport $TL2_UDP_PORT2 \
	--sport $UNPRIVPORTS \
	-j ACCEPT
$IP6TABLES -A gaming_pc_in -p tcp --sport $UNPRIVPORTS \
	--dport $TL2_TCP_PORT1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_in -p udp --sport $UNPRIVPORTS \
	--dport $TL2_UDP_PORT2 \
	-j ACCEPT

	--dport $BITTORENT_UDP_PORT_RNG1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $BITTORENT_TCP_PORT_RNG1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $BITTORENT_TCP_PORT1 \
	--dport $UNPRIVPORTS \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p udp --sport $BITTORENT_UDP_PORT1 \
	--dport $UNPRIVPORTS \
	-j ACCEPT
$IP6TABLES -A gaming_pc_in -p udp --sport $UNPRIVPORTS \
	--dport $BITTORENT_UDP_PORT_RNG1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_in -p tcp --sport $UNPRIVPORTS \
	--dport $BITTORENT_TCP_PORT_RNG1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_in -p tcp --sport $UNPRIVPORTS \
	--dport $BITTORENT_TCP_PORT2 \
	-j ACCEPT


##############################
# Steam
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Steam, "
fi
STEAM_FRIENDS_UDP_PORT="1200"
STEAM_SVR_SEARCH_UDP_PORT2="1713"
STEAM_UDP_PORT_RNG="3000:4999"
STEAM_UDP_PORT_RNG2="58500:58999"
STEAM_UDP_PORT_RNG3="27000:27050"
STEAM_UDP_SRC_PORT="3443"
STEAM_TCP_PORT_RNG="27000:27050"
STEAM_TCP_CROSS_CONNECT_PORT="9000"
STEAM_DED_SVR_UDP_RNG="27000:27050"
STEAM_DED_SVR_UDP_PORT1="27015"
STEAM_DED_SVR_UDP_PORT2="27020"
$IP6TABLES -A gaming_pc_out -p udp --sport $STEAM_SVR_SEARCH_UDP_PORT2 \
	--dport $UNPRIVPORTS \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_FRIENDS_UDP_PORT \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_UDP_PORT_RNG \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_UDP_PORT_RNG2 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_UDP_PORT_RNG3 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $STEAM_TCP_PORT_RNG \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $STEAM_TCP_PORT_FRIENDS_LIST \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $STEAM_TCP_CROSS_CONNECT_PORT \
	-j ACCEPT
$IP6TABLES -A gaming_pc_in -p udp --sport $UNPRIVPORTS \
	--dport $STEAM_DED_SVR_UDP_RNG \
	-j ACCEPT
$IP6TABLES -A gaming_pc_in -p udp --sport $STEAM_UDP_SRC_PORT \
	--dport $UNPRIVPORTS \
	-j ACCEPT

##############################
# Games for Windows Live
##############################
GFWL_UDP_PORT3="88"
GFWL_TCP_PORT="3074"
GFWL_UDP_PORT="3074"
GFWL_UDP_PORT2="3330"
GFW_LIVE_UDP_PORT="5555"
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "GFW Live, "
fi
$IP6TABLES -A gaming_pc_out -p udp --sport $GFW_LIVE_UDP_PORT \
	--dport $GFWL_UDP_PORT \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS \
	--dport $GFW_LIVE_UDP_PORT \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS \
	--dport $GFWL_UDP_PORT3 \
	-j ACCEPT


##############################
# Oculus Desktop
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Oculus Link, "
fi
# Constants 
OCULUS_UDP_PORT1="40004"
OCULUS_UDP_PORT_RNG1="40000:40009"
$IP6TABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS \
	 --dport $OCULUS_UDP_PORT_RNG1 \
	 -j ACCEPT


##############################
# New World
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "New World, "
fi

NEW_WORLD_UDP_PORT1="33435"
$IP6TABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS \
	 --dport $NEW_WORLD_UDP_PORT1 \
	 -j ACCEPT


##############################
# Roblox
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Roblox, "
fi

ROBLOX_UDP_PORT_RNG="49152:65535"
ROBLOX_TCP_PORT1="51007"

$IP6TABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS \
	--dport $ROBLOX_UDP_PORT_RNG  \
	-j ACCEPT

$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
        --dport $ROBLOX_TCP_PORT1  \
        -j ACCEPT


##############################
# No Man's Sky
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6) No Man's Sky, "
fi
NMS_TCP_STEAM_PORT_LIST="27015,27036"
NMS_UDP_STEAM_PORT="27015"
NMS_UDP_STEAM_PORT_RNG1="27031:27036"
NMS_UDP_SERVER_PORT_RNG1="30000:31999"
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	--dport $NMS_UDP_STEAM_PORT \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS \
	-m multiport --dports $NMS_TCP_STEAM_PORT_LIST \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS \
	--dport $NMS_UDP_STEAM_PORT_RNG1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS \
	--dport $NMS_UDP_SERVER_PORT_RNG1 \
	-j ACCEPT


##############################
# Disney Dreamlight Valley
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Disney Dreamlight Valley, "
fi
DDV_UDP_STEAM_PORT_RNG1="27050:27059"
$IP6TABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS \
	--dport $DDV_UDP_STEAM_PORT_RNG1 \
	-j ACCEPT


##############################
# Microsoft games
#############################
# Age of Empires II server ports
AOE_II_TCP_PORT="47624"
AOE_II_TCP_PORT_RANGE_1="2300:2400"
AOE_II_UDP_PORT_RANGE_2="2300:2400"
ALPHA_CENTARI_UDP_PORT_RANGE="1900:2000"
ALPHA_CENTARI_TCP_PORT="6073"

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& Microsoft Games"
fi
$IP6TABLES -A gaming_pc_out -p tcp --dport $AOE_II_TCP_PORT \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p tcp --dport $AOE_II_TCP_PORT_RANGE_1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_out -p udp --dport $AOE_II_UDP_PORT_RANGE_2 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_in -p tcp --dport $AOE_II_TCP_PORT \
	-j ACCEPT
$IP6TABLES -A gaming_pc_in -p tcp --dport $AOE_II_TCP_PORT_RANGE_1 \
	-j ACCEPT
$IP6TABLES -A gaming_pc_in -p udp --dport $AOE_II_UDP_PORT_RANGE_2 \
	-j ACCEPT


#########################################################################################
#########################################################################################
# End of machine-specific firewall rules
#########################################################################################
#########################################################################################


#########################################################################################
#########################################################################################
# TCP State Flags (Block stealth scans using illegal TCP states
#########################################################################################
#########################################################################################
# Block stealth scans
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Blocking and logging illegal TCP states."
fi
#   All bits are cleared
$IP6TABLES -A tcp_state_flags -p tcp --tcp-flags ALL NONE -j log_tcp_state
#   SYN and FIN are both set
$IP6TABLES -A tcp_state_flags -p tcp --tcp-flags SYN,FIN SYN,FIN -j log_tcp_state
#   SYN and RST are both set
$IP6TABLES -A tcp_state_flags -p tcp --tcp-flags SYN,RST SYN,RST -j log_tcp_state
#   FIN and RST are both set
$IP6TABLES -A tcp_state_flags -p tcp --tcp-flags FIN,RST FIN,RST -j log_tcp_state
#   FIN is the only bit set without the expected accompanying ACK
$IP6TABLES -A tcp_state_flags -p tcp --tcp-flags ACK,FIN FIN -j log_tcp_state
#   PSH is the only bit set without the expected accompanying ACK
$IP6TABLES -A tcp_state_flags -p tcp --tcp-flags ACK,PSH PSH -j log_tcp_state
#   URG is the only bit set without the expected accompanying ACK
$IP6TABLES -A tcp_state_flags -p tcp --tcp-flags ACK,URG URG -j log_tcp_state

#########################################################################################
# Log and drop TCP packets with bad state combinations
#########################################################################################
$IP6TABLES -A log_tcp_state -p tcp -j LOG --log-prefix "(IPv6)(D)Illegal TCP state: " \
         --log-ip-options --log-tcp-options
$IP6TABLES -A log_tcp_state -j DROP


#########################################################################################
# By-pass rule checking for ESTABLISHED exchanges
#########################################################################################
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    if [ "$RUN_SILENTLY" != "1" ]; then
	    echo "(IPv6)Setting ESTABLISHED,RELATED Connection Tracking rule."
    fi
    $IP6TABLES -A connection_tracking -m state --state ESTABLISHED,RELATED \
             -j ACCEPT

    # But drop INVALID connections
    if [ "$RUN_SILENTLY" != "1" ]; then
	    echo "(IPv6)Setting INVALID state Connection Tracking to drop."
    fi

    $IP6TABLES -A connection_tracking -m state --state INVALID -j DROP
fi


#########################################################################################
# Source Address Spoof Checks
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Source address check."
fi
# Drop packets pretending to be originating from the INTERNET IP address
$IP6TABLES -A source_address_check -s $INTERNET_IP \
	-j LOG --log-prefix "(IPv6)(D)SrcAddrCk(ownIP): "
$IP6TABLES -A source_address_check -s $INTERNET_IP -j DROP
# Refuse packets claiming to be from private networks or reserved addresses
$IP6TABLES -A source_address_check -s $UNIQUE_LOCAL_ADDRESS \
	-j LOG --log-prefix "(IPv6)(D)SrcAddrCk(UNIQUE_LOCAL_ADDRESS): " 
$IP6TABLES -A source_address_check -s $UNIQUE_LOCAL_ADDRESS -j DROP 
###########
## -cap comment out for setup testing
###########
$IP6TABLES -A source_address_check -s $LOOPBACK \
	-j LOG --log-prefix "(IPv6)(D)SrcAddrCk(Loopback): " 
$IP6TABLES -A source_address_check -s $LOOPBACK -j DROP

#########################################################################################
# Bad Destination Address and Port Checks
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Destination address check."
fi
###########
## If this is NOT operating as an internal firewall, apply the following rules
###########
if [ "$INTERNAL_FIREWALL" == "0" ]; then
	echo "There are no special IPv6 rules when operating as an internal firewall"
fi

# TCP unprivileged ports
# Deny connection requests to NFS, SOCKS and X Window ports (except internal X Window requests)
$IP6TABLES -A destination_address_check -p tcp -m multiport \
        --destination-port $NFS_PORT,$SOCKS_PORT,$SQUID_PORT --syn \
	-j LOG --log-prefix "(IPv6)(D)DstAddrCk(CmnPrtsTCP): " 
$IP6TABLES -A destination_address_check -p tcp -m multiport \
        --destination-port $NFS_PORT,$SOCKS_PORT,$SQUID_PORT \
        --syn -j DROP 
$IP6TABLES -A destination_address_check ! -s $LAN_SUBNET -p tcp --syn --destination-port $XWINDOW_PORTS \
	-j LOG --log-prefix "(IPv6)(D)DstAddrCk(Xwindow-Ext): " 
$IP6TABLES -A destination_address_check ! -s $LAN_SUBNET -p tcp --syn \
        --destination-port $XWINDOW_PORTS -j DROP 
# UDP unprivileged ports
# Deny connection requests to NFS and lockd ports
$IP6TABLES -A destination_address_check -p udp -m multiport \
	--destination-port $NFS_PORT,$LOCKD_PORT \
	-j LOG --log-prefix "(IPv6)(D)DstAddrCk(CmnPrtsUDP): " 
$IP6TABLES -A destination_address_check -p udp -m multiport \
        --destination-port $NFS_PORT,$LOCKD_PORT -j DROP 

#########################################################################################
# Refuse any connections from problem sites
#########################################################################################
# /opt/iptables/rules.blocked.ips.v6 contains a list of
# $IP6TABLES -A input -i $INTERNET_IF -s <address/mask> -j DROP
# rules to block all access.
# Refuse packets claiming to be from the banned list
if [ -f /opt/iptables/rules.blocked.ips.v6 ]; then
	if [ "$RUN_SILENTLY" != "1" ]; then
		echo "(IPv6)Setting rules for the banned IPv6 list..."
	fi
    . /opt/iptables/rules.blocked.ips.v6
fi

#########################################################################################
# Logging Rules Prior to Dropping by the Default Policy
#########################################################################################
#########################################################################################
# Remove log chain established for Link Local rule processing and re-establish it at the
# end of the updated chain policies now that we have a Global IP address
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Removing link local log chains: "
fi
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "flush & delete log_in, "
fi
$IP6TABLES --flush log_in
$IP6TABLES --delete INPUT -j log_in
$IP6TABLES --delete-chain log_in

if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "flush & delete log_out, "
fi
$IP6TABLES --flush log_out
$IP6TABLES --delete OUTPUT -j log_out
$IP6TABLES --delete-chain log_out

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "flush & delete log_forward. "
fi
$IP6TABLES --flush log_forward
$IP6TABLES --delete FORWARD -j log_forward
$IP6TABLES --delete-chain log_forward

if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Creating new drop log chains: "
fi
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "log_in, "
fi
$IP6TABLES --new-chain log_in

if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "log_out, "
fi
$IP6TABLES --new-chain log_out

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& log_forward. "
fi
$IP6TABLES --new-chain log_forward

################################
# Log incoming unmatched rules
################################

##############
# ICMP rules #
##############
$IP6TABLES -A log_in -p icmpv6 ! --icmpv6-type echo-request -m limit \
	-j LOG --log-prefix "(IPv6)(D)IN-drop: "

##############
# TCP rules  #
##############
$IP6TABLES -A log_in -p tcp --dport 0:134 -j LOG --log-prefix "(IPv6)(D)IN-drop: "
# Skip Microsoft RPC at 135
$IP6TABLES -A log_in -p tcp --dport 136 -j LOG --log-prefix "(IPv6)(D)IN-drop: "
# Skip Microsoft NETBIOS crap at 137, 138, & 139
#137	netbios-ns	NETBIOS Name Service
#138	netbios-dgm	NETBIOS Datagram Service
#139	netbios-ssn	NETBIOS Session Service
$IP6TABLES -A log_in -p tcp --dport 140:142 -j LOG --log-prefix "(IPv6)(D)IN-drop: "
# skip imap
$IP6TABLES -A log_in -p tcp --dport 144:444 -j LOG --log-prefix "(IPv6)(D)IN-drop: "
# skip microsoft-ds
$IP6TABLES -A log_in -p tcp --dport 446:65535 -j LOG --log-prefix "(IPv6)(D)IN-drop: "

################################
# Log outgoing unmatched rules
################################
# Don't log rejected outgoing ICMP destination-unreachable packets
$IP6TABLES -A log_out -p icmpv6 \
         --icmpv6-type destination-unreachable \
	 -j LOG --log-prefix "(IPv6)(D)OUT-icmp-dest-unrch-drop: "
$IP6TABLES -A log_out -p icmpv6 \
         --icmpv6-type destination-unreachable -j DROP
# But log everything else
$IP6TABLES -A log_out -j LOG --log-prefix "(IPv6)(D)OUT-drop: "

######################
# log_forward rules  #
######################
# Log everything that did not match and ACCEPT rule
$IP6TABLES -A log_forward -j LOG --log-prefix "(IPv6)(D)FWD-drop: "


#########################################################################################
# Set up the jumps from the built-in INPUT, OUTPUT, and FORWARD chains to our standard 
# user chains
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Creating the jump rules to the user-defined chains:"
fi

# If TCP: Check for common stealth scan TCP state patterns
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6) TCP state, "
fi
$IP6TABLES -A INPUT  -p tcp -j tcp_state_flags
$IP6TABLES -A OUTPUT -p tcp -j tcp_state_flags
$IP6TABLES -A FORWARD -p tcp -j tcp_state_flags

# If we are doing connection tracking, we can bypass a lot of checks
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    if [ "$RUN_SILENTLY" != "1" ]; then
	    echo -n "conn track, "
    fi
    # By-pass the firewall filters for established exchanges
    $IP6TABLES -A INPUT  -j connection_tracking
    $IP6TABLES -A OUTPUT -j connection_tracking
    $IP6TABLES -A FORWARD -j connection_tracking
fi

# Test for illegal source and destination addresses in incoming packets
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "source addr check, "
fi
$IP6TABLES -A INPUT ! -p tcp -i $INTERNET_IF ! -s $LAN_SUBNET -j source_address_check
$IP6TABLES -A INPUT -p tcp --syn -i $INTERNET_IF ! -s $LAN_SUBNET -j source_address_check
$IP6TABLES -A FORWARD ! -p tcp -i $INTERNET_IF ! -s $LAN_SUBNET -j source_address_check
$IP6TABLES -A FORWARD -p tcp --syn -i $INTERNET_IF ! -s $LAN_SUBNET -j source_address_check

# Test for illegal destination addresses in incoming packets
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& dest addr check."
fi

# Test for illegal destination addresses in incoming packets
$IP6TABLES -A INPUT  -j destination_address_check

# Test for illegal destination addresses in outgoing packets
$IP6TABLES -A OUTPUT -j destination_address_check

# Test for illegal destination addresses in forwarded packets
$IP6TABLES -A FORWARD -j destination_address_check

#########################################################################################
# Add the Global IP chains 
#########################################################################################

# Normal routed packets coming from the Internet that are destined to us 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6)Add the global chains: ext if in, "
fi
$IP6TABLES -A INPUT -i $INTERNET_IF -d $INTERNET_IP -j ext_if_in

# Packets coming from our interal LAN destined to the LAN IP Address
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "LAN if in, "
fi
$IP6TABLES -A INPUT -i $LAN_IF -d $LAN_IP -j lan_if_in

# Packets being forwarded from the Internet to our internal LAN
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ext -> int, "
fi
$IP6TABLES -A FORWARD -i $INTERNET_IF -o $LAN_IF -j ext_int

# Packets being forwarded from our internal LAN to our external IP address
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "LAN -> ext if, "
fi
$IP6TABLES -A INPUT -i $LAN_IF -d $INTERNET_IP -j ext_if_lan_in

# Packets generated from our external IP address destined to addresses on the Internet
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ext if out, "
fi
$IP6TABLES -A OUTPUT -o $INTERNET_IF -s $INTERNET_IP -j ext_if_out

# Packets generated from our LAN IP Address destined to the interal LAN
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "LAN if out, "
fi
$IP6TABLES -A OUTPUT -o $LAN_IF -s $LAN_IP -j lan_if_out

# Packets being forwarded from our internal LAN to the Internet
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "(IPv6) int -> ext, "
fi
$IP6TABLES -A FORWARD -i $LAN_IF -o $INTERNET_IF -j int_ext

# Packets being forwarded from our external IP address to our internal LAN
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "ext if -> LAN, "
fi
$IP6TABLES -A OUTPUT -o $LAN_IF -s $INTERNET_IP -j ext_if_lan_out


#########################################################################################
# Log anything of interest that fell through,
# before the default policy drops the packet.
#########################################################################################
$IP6TABLES -A INPUT  -j log_in 
$IP6TABLES -A OUTPUT -j log_out 
$IP6TABLES -A FORWARD -j log_forward

#########################################################################################
# Open up the flood gates by dropping the first rule on the input and forward chains,
# which was explicitly set to DROP all traffic (except loopback)
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6) "
	echo -n "(IPv6)Restoring normal IP forwarding: "
    	logger "$(basename "$0")(IPv6): Rules applied. Restoring normal IP forwarding."
fi


if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)Removing DROP rule on FORWARD chain. "
fi
$IP6TABLES -D FORWARD 1

# We no longer do this every time we rerun the rules. We assume ipv6 forwarding has 
# been enabled elsewhere and left on.

# if [ "$RUN_SILENTLY" != "1" ]; then
# 	echo "(IPv6)Turn on IPv6 forwarding. "
# fi
# echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

# PROC_INTERNET_RA_PATH='/proc/sys/net/ipv6/conf/'$INTERNET_IF'/accept_ra'
# if [ "$RUN_SILENTLY" != "1" ]; then
# 	echo "(IPv6)Force accepting router advertisements on the $INTERNET_IF (2 > $PROC_INTERNET_RA_PATH) "
# fi
# echo 2 > $PROC_INTERNET_RA_PATH

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "(IPv6)done at:" `date`
    	logger "$(basename "$0")(IPv6): Done."
fi

# ip6tables-save > ip6tables.save.atEnd.txt

exit 0


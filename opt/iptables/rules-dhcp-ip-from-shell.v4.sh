#!/bin/bash

# Set the following to "0" to turn on default logging or to "1" to run silently.
RUN_SILENTLY="0"

if [ "$RUN_SILENTLY" != "1" ]; then
 	echo "Starting firewalling... "
fi

######################################################################
######################################################################
# Some definitions for easy maintenance. #
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
 	echo "Setting definitions... "
fi
IPTABLES=/sbin/iptables

######################################################################
# Firewall Operation Definitions
######################################################################
# Set to 1 if connection tracking is supported
USE_CONNECTION_TRACKING="1"

# This firewall is a DHCP client on the WAN (i.e., uses a dynamically assigned IP address
ISA_DHCP_CLIENT="1"

# This firewall is a DHCP server for the LAN (e.g., is a DHCP server to an internal network)
ISA_DHCP_SERVER="1"

######################################################################
# Load modules
######################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
    logger "$(basename "$0"): Starting to load iptables rules."
    echo -n "Loading modules: "
fi

if [ "$RUN_SILENTLY" != "1" ]; then
    echo -n "ip_tables, "
fi
modprobe ip_tables

if [ "$RUN_SILENTLY" != "1" ]; then
    echo -n "nf_nat, "
fi
modprobe nf_nat

if [ "$RUN_SILENTLY" != "1" ]; then
    echo -n "iptable_filter, "
fi
modprobe iptable_filter

if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "iptable_nat, "
fi
modprobe iptable_nat

if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "iptable_mangle"
fi
modprobe iptable_mangle

if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
    if [ "$RUN_SILENTLY" != "1" ]; then
            echo -n ", nf_conntrack, "
    fi
    modprobe nf_conntrack       # Gives iptables ability to track connections

    if [ "$RUN_SILENTLY" != "1" ]; then
         echo -n "nf_conntrack_ftp, "
    fi
    modprobe nf_conntrack_ftp   # Gives iptables ability to track outbound FTP connections

    if [ "$RUN_SILENTLY" != "1" ]; then
        echo -n "& nf_nat_ftp"
    fi
    modprobe nf_nat_ftp         # Gives iptables ability to track outbound FTP connections through NAT firewall
fi

if [ "$RUN_SILENTLY" != "1" ]; then
        echo "."
        logger "$(basename "$0"): Connection tracking and NAT modules loaded (if enabled)"
fi

 
######################################################################
# Reserved private (internal-non routable) IP Addresses
######################################################################
LOOPBACK="127.0.0.0/8"              # reserved loopback address range
CLASS_A="10.0.0.0/8"                # class A private networks
CLASS_B="172.16.0.0/12"             # class B private networks
CLASS_C="192.168.0.0/16"            # class C private networks
CLASS_D_MULTICAST="224.0.0.0/4"     # class D multicast addresses
# Special Class D Multicast IP addresses
IGMP_MULTICAST="224.0.0.1"          # IGMP Verizon
IGMP_MULTICAST_V3="224.0.0.22"      # IGMP v3
DNS_MULTICAST="224.0.0.251"         # Multicast DNS
CLASS_E_RESERVED_NET="240.0.0.0/5"  # class E reserved addresses
# Some useful reminders
# x.x.x.0 - x.x.7.255 = /22 = netmask 255.255.252.0   = 1024 IP addrs / 1022 hosts
# x.x.x.0 - x.x.3.255 = /23 = netmask 255.255.254.0   =  512 IP addrs /  510 hosts
# x.x.x.0 - x.x.x.255 = /24 = netmask 255.255.255.0   =  256 IP addrs /  254 hosts
# x.x.x.0 - x.x.x.127 = /25 = netmask 255.255.255.128 =  128 IP addrs /  126 hosts
# x.x.x.0 - x.x.x.63  = /26 = netmask 255.255.255.192 =   64 IP addrs /   62 hosts
# x.x.x.0 - x.x.x.31  = /27 = netmask 255.255.255.224 =   32 IP addrs /   30 hosts
# x.x.x.0 - x.x.x.15  = /28 = netmask 255.255.255.240 =   16 IP addrs /   14 hosts
# x.x.x.0 - x.x.x.7   = /29 = netmask 255.255.255.248 =    8 IP addrs /    6 hosts
# x.x.x.0 - x.x.x.3   = /30 = netmask 255.255.255.252 =    4 IP addrs /    2 hosts
#  where the first (network number) and last (broadcast addr) are
#  not assignable. (Hence, a /28 network has at most 14 usable IPs. If
#  the ISP's router uses an IP address, then only 13 are left for the
#  end user.)


######################################################################
# Special Network IP Addresses and Ports
######################################################################
BROADCAST_SRC="0.0.0.0"             # broadcast source address
INTERNAL_BROADCAST_DEST="192.168.115.255" # broadcast destination address
BROADCAST_DEST="255.255.255.255"    # broadcast destination address
PRIVPORTS="0:1023"                  # wellknown, privileged port range
UNPRIVPORTS="1024:65535"            # unprivileged port range
ANYWHERE="any/0"                    # match any IP address


######################################################################
######################################################################
# Interface definitions
######################################################################
######################################################################


######################################################################
# Loopback
######################################################################
LOOPBACK_IF="lo" 		# Local loopback interface


######################################################################
######################################################################
# WAN side definitions (dynamically created)
######################################################################
######################################################################
INTERNET_IF="enp2s0" 		# WAN (Internet) NIC device name
echo 'Internet interface:'\'$INTERNET\'
logger "$(basename "$0"): Internet inteface: $INTERNET"

INTERNET_SUBNET=""
IP_ADDR_RETRY_COUNT=0 		# Current IP Address DHCP resolution retry count
IP_ADDR_RETRY_MAX=20    	# Maximum number of times to retry before giving up
IP_ADDR_RETRY_SLEEP_TIME=10 	# Seconds to sleep between retrys

getIpv4Address() {
 	INTERNET_SUBNET=$(/sbin/ip -o -4 addr list ${INTERNET_IF} | egrep -v '169.254' | awk '{print $4}')
 	IP_ADDR_RETRY_COUNT=$((IP_ADDR_RETRY_COUNT+1))
}

getIpv4Address
while [ -z "$INTERNET_SUBNET" -a $IP_ADDR_RETRY_COUNT -le $IP_ADDR_RETRY_MAX ]; do
 	echo "Internet IPv4 subnet and IPv4 IP address not yet known. Sleeping for $IP_ADDR_RETRY_SLEEP_TIME seconds."
 	sleep $IP_ADDR_RETRY_SLEEP_TIME 
 	getIpv4Address
done

if [ -z "$INTERNET_SUBNET" ]; then
 	echo "Internet IPv4 subnet and IPv4 IP not resolved. Exiting."
 	logger "$(basename "$0"): Internet subnet and IP not resolved. Exiting."
 	exit 1
fi
echo 'Internet subnet:'\'$INTERNET_SUBNET\'
logger "$(basename "$0"): Internet subnet: $INTERNET_SUBNET"

# Our publicly visible IP address on that net
INTERNET_IP=$(/sbin/ip -o -4 addr list ${INTERNET_IF} | egrep -v '169.254' | awk '{print $4}' | cut -d/ -f1)
echo 'Internet IP: '\'$INTERNET_IP\'
logger "$(basename "$0"): Internet IP: $INTERNET_IP"

# Our subnet's network base address
INTERNET_BASE=$(/sbin/ip -o -4 addr list ${INTERNET_IF} | egrep -v '169.254' | awk '{print $4}' | cut -d. -f1-3 | xargs -I {} echo -n {}'.0')
echo 'Internet base:' \'$INTERNET_BASE\'
logger "$(basename "$0"): Internet base: $INTERNET_BASE"

# Our subnet's gateway address
INTERNET_GATEWAY=$(/sbin/ip -o -4 route | egrep -v '169.254' | awk '/default/ {print $3; exit}')
echo 'Internet gateway:' \'$INTERNET_GATEWAY\'
logger "$(basename "$0"): Internet gateway: $INTERNET_GATEWAY"

# Our subnet's gateway address
INTERNET_BROADCAST=$(/sbin/ip -o -4 addr list ${INTERNET_IF} | egrep -v '169.254' | awk '{print $6}')
echo 'Internet broadcast:' \'$INTERNET_BROADCAST\'
logger "$(basename "$0"): Internet broadcast: $INTERNET_BROADCAST"


######################################################################
######################################################################
# LAN side definitions (static)
######################################################################
######################################################################
LAN_IF="enp4s0"                      # internal LAN NIC device name
LAN_SUBNET="192.168.115.0/24"        # internal LAN network IP
LAN_IP="192.168.115.1"               # firewall's internal interface address on that net
LAN_BROADCAST="192.168.115.255"      # internal LAN broadcast addr

#########################################################################################
# Server IP Addresses
#########################################################################################

#########################################################################################
# DHCP
#########################################################################################
LOCAL_DHCP_SERVER="192.168.115.1"    # if there is one
REMOTE_DHCP_SERVER=$INTERNET_GATEWAY # external DHCP server
ISP_DELEGATED_DHCP_SERVER="69.241.64.0/18" # ISP's delegated server from RAs
LAN_SUBNET_RANGE="192.168.115.0/24"  # LAN address range (internal, non routable)

#########################################################################################
# DNS
#########################################################################################
LOCAL_NAMESERVER=$INTERNET_IP        # My Local Caching/Forwarding DNS server on the outside IF
#echo 'Local nameserver: ' $LOCAL_NAMESERVER
LOCAL_NAMESERVER_INT="192.168.115.1" # My Local Caching/Forwarding DNS server on the inside LAN IF
NAMESERVER_1="8.8.8.8"               # Google's Open DNS server (primary)
NAMESERVER_2="8.8.4.4"               # Google's Open DNS server (secondary)
NAMESERVER_3="71.252.0.12"           # Verizon's Reston, VA Nameserver primary
NAMESERVER_4="68.237.161.12"         # Verizon's New York, NY Nameserver primary
# NAMESERVER_3="75.75.75.75"         # Xfinity Nameserver primary
# NAMESERVER_4="75.75.76.76"         # Xfinity Nameserver secondary
CLOUDFLARE_DNS_SERVER="1.1.1.1"      # Cloudflare's Open DNS Server

#########################################################################################
# SMTP
#########################################################################################
ALT_SMTPS_PORT="587"                 # Alternate listening port for secure SMTP (default is 465)
REMOTE_SMTP_SERVER="172.253.122.18"  # external mail server (mail.google.com)

#########################################################################################
# NTP
#########################################################################################
# The timeserver variables are placeholders. Current NTP requests are allowed from any
# machine inside or including the firewall.
TIME_SERVER1="128.4.0.0/16"          # NTP server louie.udel.edu
TIME_SERVER2="128.175.7.39"          # NTP server louie.udel.edu
TIME_SERVER3="128.182.58.100"        # NTP server fuzz.psc.edu
TIME_SERVER4="128.2.136.71"          # NTP server ntp-1.ece.cmu.edu
TIME_SERVER5="128.2.129.21"          # NTP server ntp-2.ece.cmu.edu
TIME_SERVER6="128.175.0.0/16"        # NTP server louie.udel.edu
NEWS_SERVER="any/0"

#########################################################################################
# Other Internal Servers & Ports
#########################################################################################
STEAMDECK_DOCK="192.168.115.46"       # Steamdeck in Dock with Ethernet
STEAMDECK_WL="192.168.115.47"         # Steamdeck wireless
MYLAPTOP="192.168.115.48"             # Windows Laptop (via wireless)
GAMINGPC="192.168.115.49"             # The Beast
FILESERVER="192.168.115.50"           # File Server and Backup
IPHONE="192.168.115.51"               # iPhone
ORBI="192.168.115.52"                 # Netgear Orbi base as a mesh Wireless Access Point
ECOBEE3="192.168.115.53"              # Ecobee 3 Thermostat
SAMSUNG23U="192.168.115.54"           # Samsung Galaxy S23 Ultra (Work)
SAMSUNGS24="192.168.115.55"           # Samsung Galaxy S24
FAMROOMECHO="192.168.115.56"          # Amazon Echo 4th Gen (Family Room)
OFFICEECHO="192.168.115.57"           # Amazon Echo DOT Gen 4 (Office)
GALAXYTAB="192.168.115.58"            # Galaxay Tablet
FRONTLIGHTS="192.168.115.59"          # Smart swith for front lights
KINDLE="192.168.115.60"               # Amazon Kindle
ROKU="192.168.115.61"                 # Roku Ultra
VPN_TUNNEL="192.168.115.62"           # System needing a VPN Tunnel
WIRELESSPLUG1="192.168.115.63"        # 2.4GHz wireless plug #1
ORBISATELLITE="192.168.115.64"        # Netgear Orbi satellite
GUESTGAMER="192.168.115.65"           # Guest gaming box
WIRELESSPLUG2="192.168.115.66"        # 2.4GHz wireless plug #2
NINTENDOSWITCH="192.168.115.67"       # Nintendo Switch
PRINTER="192.168.115.68"              # Networked Printer


VPN_CLIENT_MAIL_PORTS="2222:2223" # VPN server port
PRINTER_CTRL_PORT1="161" # some port used by the printer
PRINTER_CTRL_PORT2="631" # some port used by the printer
PRINTER_TCP_PRINTING="9100" # TCP port for network printing

######################################################################
# Common Port Numbers
######################################################################
# Google Services
GOOGLE_TALK_UDP_PORT="3478"
GOOGLE_TALK_UDP_PORT_RNG="19302:19309"
GOOGLE_TALK_UDP_PORT_RNG2="26500:26501"
GOOGLE_TALK_TCP_PORT="5222"
GOOGLE_TALK_SERVER="111.206.200.2"
GOOGLE_TALK_SERVER2="52.221.144.129"
GOOGLE_TALK_SERVER3="52.74.212.166"
GGOGLE_TALK_SERVER_RANGE="142.250.111.0/24"
GGOGLE_TALK_SERVER_RANGE2="74.125.39.0/24"
GOOGLE_PLAYSTORE_SERVER="74.125.28.188"
GOOGLE_PLAYSTORE_SERVER2="173.194.204.188"
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
MULTICAST_DNS="5353"                # Network remote port used by Apple Bonjour, TiVo Android app, etc.

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

######################################################################
# Definition of user chains:
######################################################################
#  Remember: the firewall is the center of our universe as far as firewall rules
#  are concerned. Every rule and chain is taken from the point of view of the
#  firewall. That is why lan_if_in refers to traffic coming in from the LAN
#  rather than traffic coming in from the Internet.
#
#  ext_if_in:
#       Packets destined to our external IP address from an addresses on
#       the Internet
#  ext_if_out:
#       Packets generated from our external IP address destined to addresses on
#       the Internet
#  ext_if_icmp_out:
#       ICMP requests made from our firewall machine to a destination on the Internet
#  ext_if_icmp_in:
#       ICMP requests made from sources on the Internet and destined to
#       external interface (the firewall machine itself)
#  dropped_log_in:
#       The chain used to log traffic at the external interface from the Internet
#  ext_if_log_out:
#       The chain used to log traffic leaving the external interface to the Internet
#  int_ext:
#       Packets on the forwarding chain generated by our internal LAN and destined
#       to the Internet
#  ext_int:
#       Packets on the forwarding chain coming from the Internet and destined to
#       one of the machines on our internal LAN
#  int_ext_icmp:
#       ICMP packets on the forwarding chain from our LAN machines to
#       the destinations on the Internet. (ICMP requests only(
#  ext_int_icmp:
#       ICMP packets on the forwarding chain from the Internet destined to machines
#       on our LAN (responses to our ICMP requests only)
#  lan_if_in:
#       Packets generated from our internal IP address destined to addresses on
#       the Internet and are to be routed through the firewall and therefore are
#       coming "in" from our LAN
#  lan_if_out:
#       Packets that have been routed through or generated by the firewall machine
#       that are destined to machines on the internl LAN. Therefore, these will be
#       sent "out" to our LAN
#  lan_if_multi_in:
#       Packets generated from our internal IP address destined to multicast
#       addresses and are to be routed to the firewall and therefore are
#       coming "in" from our LAN
#  lan_if_multi_out:
#       Packets that have been routed through or generated by the firewall machine
#       that are responses from multicast requests to inside our LAN that are
#       sent "out" to our LAN
#  lan_if_icmp_in:
#       ICMP packets generated by internal LAN machines toward the internal LAN
#       interface or the external WAN interface on the firewall
#  lan_if_icmp_out:
#       ICMP packets generated by the LAN or WAN interfaces on the firewall destined to
#       the internal LAN machines (primary for responses and pinging LAN machines)
#  LAN_udp_firewall_request:
#       UDP packets generated by the firewall machine specifically aimed at one of the
#       internal lan machines
#  LAN_udp_firewall_response:
#       UDP packets generated from the internal lan machines as responses to requests
#       by the firewall machine
#  LAN_tcp_firewall_request:
#       TCP packets generated by the firewall machine specifically aimed at one of the
#       internal lan machines
#  LAN_tcp_firewall_response:
#       TCP packets generated from the internal lan machines as responses to requests
#       by the firewall machine
#  ext_if_lan_in:
#       Packets generated from the LAN that are destined to the firewall's external
#       IP address on the forward chain
#  ext_if_lan_out:
#       Packets destined to the LAN that are generated by the firewall's external
#       IP address on the forward chain (in response to packets generated by the
#       LAN to this interface.
#  tcp_state_flags:
#       Special chain used to log and drop packets with illegal TCP state combinations
#  connection_tracking:
#       Special chain used to detect Established & Related traffic to short-circuit
#       further testing. (Established & Related traffic is quickly accepted.)
#  source_address_check:
#       Special chain used to check the validity of the source address of packets
#       coming from the internet (usually)
#  destination_address_check:
#       Special chain used to check the validity of the destination address of packets
#       coming from the internet (usually) (typically watcjing for spoofed broadcast
#       packets)
#  lcl_dns_srv_to_trust_dns_srv:
#       Used to check our local DNS server making queries to the primary DNS
#       servers of our ISP and/or our trusted slave servers and those servers
#       making requests of our DNS server for the domains we are the master of
#  lcl_dns_srv_fm_trust_dns_srv:
#       Used to check our local DNS server getting responses from the primary DNS
#       servers of our ISP and/or our trusted slave servers and those servers
#       making requests of our DNS server for the domains we are the master of
#  trusted_dns_srv_LAN_query:
#       Chain used to check the validity of requests made to our local DNS servers
#       from machines within our LAN
#  lcl_dns_srv_rmt_query:
#       Chain used to check the validity of requests made to our local DNS servers
#       from the Internet
#  trusted_dns_srv_LAN_response:
#       Used to check the response of local DNS server going to our local LAN
#  lcl_dns_srv_rmt_response:
#       Used to check the response of local DNS server going to requestors on the
#       Internet
#  rmt_dns_srv_query:
#       Chain used to check the validity of requests made to remote (trusted) DNS
#       servers from the internal LAN and external IP (normal requests)
#  rmt_dns_srv_response:
#       Used to check the validity of reponses coming from a remote DNS server to
#       our internal LAN  and external IP (normal requests)
#  lcl_tcp_client_request:
#       A request from our external interface (firewall) or our LAN machines to a
#       remote TCP-based server on the Internet
#  rmt_tcp_srv_response:
#       A response from a remote TCP-based server on the Internet to our firewall
#       or LAN machines (in response to a request)
#  rmt_tcp_client_request:
#       A request from a client on the Internet to a TCP-based service on our firewall
#  lcl_tcp_srv_response:
#       A response from our firewall TCP-based server to a client on the Internet
#  LAN_tcp_client_request:
#       Internal LAN TCP clients requests to services that appear on the firewall
#       machine (whether that's where they truly are or not)
#  tcp_srv_LAN_response:
#       Repsonses from the firewall TCP-based services back to clients on our internal
#       LAN
#  local_udp_client_request:
#       A request from our external interface (firewall) or our LAN machines to a
#       remote UDP-based server on the Internet
#  remote_udp_srv_response:
#       A response from a remote UDP-based server on the Internet to our firewall
#       or LAN machines (in response to a request)
#  lcl_dhcp_client_query:
#  rmt_dhcp_srv_response:
#  local_dhcp_server_query:
#  local_dhcp_srv_response:
#  log_tcp_state:

USER_CHAINS="ext_if_in                  ext_if_out \
         ext_if_icmp_in                 ext_if_icmp_out \
         dropped_log_in                 dropped_log_out \
         int_ext                        ext_int \
         int_ext_icmp                   ext_int_icmp \
         lan_if_in                      lan_if_out \
         lan_if_icmp_in                 lan_if_icmp_out \
         lan_if_multi_in                lan_if_multi_out \
         LAN_udp_firewall_request       LAN_udp_firewall_response \
         LAN_tcp_firewall_request       LAN_tcp_firewall_response \
         ext_if_lan_out                 ext_if_lan_in \
         tcp_state_flags                connection_tracking  \
         source_address_check           destination_address_check  \
         lcl_dns_srv_to_trust_dns_srv   lcl_dns_srv_fm_trust_dns_srv \
         trusted_dns_srv_LAN_query      lcl_dns_srv_rmt_query \
         trusted_dns_srv_LAN_response   lcl_dns_srv_rmt_response \
         rmt_dns_srv_query              rmt_dns_srv_response  \
         lcl_tcp_client_request         rmt_tcp_srv_response \
         local_udp_client_request       remote_udp_srv_response \
         remote_udp_client_request      local_udp_srv_response \
         rmt_tcp_client_request         lcl_tcp_srv_response \
         LAN_tcp_client_request         tcp_srv_LAN_response \
         LAN_udp_client_request         udp_srv_LAN_response \
         lcl_dhcp_client_query          rmt_dhcp_srv_response \
         LAN_dhcp_client_query          LAN_dhcp_srv_response \
         steamdeck_in                   steamdeck_out \
         vpn_machine_in                 vpn_machine_out \
         laptop_in                      laptop_out \
         network_printer_in             network_printer_out \
         file_server_in                 file_server_out \
         gaming_pc_in                   gaming_pc_out \
         guest_gamer_in                 guest_gamer_out \
         wap_in                         wap_out \
         smartplugswitch_in             smartplugswitch_out \
         samsungphone_in                samsungphone_out \
         galaxytablet_in                galaxytablet_out \
         oculusquest2_in                oculusquest2_out \
         roku_in                        roku_out \
         ecobee3_in                     ecobee3_out \
         switch_in                      switch_out \
         wirelessplug_in                wirelessplug_out \
         log_in                         log_out \
         log_tcp_state                  log_forward"

######################################################################
######################################################################
# Firewall Rules #
######################################################################
######################################################################
# Stop all traffic while we set the rules
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Applying iptables firewall rules: ..."
	echo "Stopping all traffic except on loopback interface while the "
	echo "rules are being reset..."
 	logger "$(basename "$0"): Applying iptables firewall rules: ..."
 	logger "$(basename "$0"): Stopping all traffic except on loopback interface while the rules are being reset..." 
fi
$IPTABLES -I INPUT 1 ! -i $LOOPBACK_IF -j DROP
$IPTABLES -I FORWARD 1 -j DROP

# Flush any existing rules from all chains
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Flushing all previous rules: ... "
 	logger "$(basename "$0"): Flushing all previous rules: ..."
fi
$IPTABLES -F
$IPTABLES -F -t nat
$IPTABLES -F -t mangle

$IPTABLES -I INPUT 1 ! -i $LOOPBACK_IF -j DROP
$IPTABLES -I FORWARD 1 -j DROP

# Remove any pre-existing user-defined chains
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Deleting user-defined chains: ..."
 	logger "$(basename "$0"): Deleting user-defined chains: ..."
fi
$IPTABLES --delete-chain
$IPTABLES -t nat --delete-chain
$IPTABLES -t mangle --delete-chain

# Unlimited traffic on the LOOPBACK interface
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Enabling unlimited internal traffic on the loopback interface ..."
 	logger "$(basename "$0"): Enabling unlimited internal traffic on the loopback interface ..."
fi
$IPTABLES -A INPUT -i $LOOPBACK_IF -j ACCEPT
$IPTABLES -A OUTPUT -o $LOOPBACK_IF -j ACCEPT

# Set the default policy to drop, however we often drop or reject 
# within the chains we're about to define as well.
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Setting default policy to DROP"
 	logger "$(basename "$0"): Setting default policy to DROP"
fi
$IPTABLES -t filter --policy INPUT DROP
$IPTABLES -t filter --policy OUTPUT DROP
$IPTABLES -t filter --policy FORWARD DROP

# A bug that showed up as of the Red Hat 7.2 release results
# in the following 5 default policies breaking the firewall
# initialization: (-cap They were all DROP)

# Incoming packets on an interface before passing the packet to a routing function.
$IPTABLES -t nat --policy PREROUTING ACCEPT
# Locally generated outgoing packets before the routing decision has been made
$IPTABLES -t nat --policy OUTPUT ACCEPT
# Source changes made to outgoing packets after the routing decision has been made
$IPTABLES -t nat --policy POSTROUTING ACCEPT
# Mangle incoming packets before any routing or local delivery
$IPTABLES -t mangle --policy PREROUTING ACCEPT
# Mangle locally generated outgoing packets
$IPTABLES -t mangle --policy OUTPUT ACCEPT

###############################################################
# Create the user-defined chains
###############################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Creating the user-defined chains..."
 	logger "$(basename "$0"): Creating the user-defined chains, logs, and rules."
fi
for i in $USER_CHAINS; do
	$IPTABLES -N $i
done


###############################################################
# Netfilter supported protection
###############################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Setting broadcast echo protection, source routed packets, "
	echo " TCP SYN Cookie protection, disabling ICMP redirect, "
	echo " disabling ICMP redirect message sending, IP spoofing protection, "
	echo " disabling explcit congestion notification"
	echo " and enabling log of impossible addresses. "
fi
# Enable broadcast echo protection
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Disable Source Routed Packets
for f in /proc/sys/net/ipv4/conf/*/accept_source_route; do
	echo 0 > $f
done

# Enable TCP SYN Cookie Protection
echo 1 >/proc/sys/net/ipv4/tcp_syncookies

# Disable ICMP Redirect Acceptance
for f in /proc/sys/net/ipv4/conf/*/accept_redirects; do
	echo 0 > $f
done

# Disable ICMP Redirect Message Sending
for f in /proc/sys/net/ipv4/conf/*/send_redirects; do
	echo 0 > $f
done

# Enable IP spoofing protection
# turn on Source Address Verification
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
	echo 1 > $f
done

# (stop logging martians -- the NIM100 won't shut up) Log packet with impossible addresses
for f in /proc/sys/net/ipv4/conf/*/log_martians; do
	echo 0 > $f
done

if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Establishing services: "
fi

#########################################################################################
# Domain Name Server - DNS (local DNS server making queries to 
# remote, trusted DNS servers and remote, trusted DNS servers
# making queries to local DNS server)
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "DNS (local-to-trusted), "
fi

#####################
# Set up the chains #
#####################
# Set up the jump to the chains for UDP requests
$IPTABLES -A ext_if_out -p udp --sport domain --dport domain -j lcl_dns_srv_to_trust_dns_srv
$IPTABLES -A ext_if_in -p udp --sport domain --dport domain -j lcl_dns_srv_fm_trust_dns_srv
$IPTABLES -A ext_if_out -p udp --sport domain-s --dport domain-s -j lcl_dns_srv_to_trust_dns_srv
$IPTABLES -A ext_if_in -p udp --sport domain-s --dport domain-s -j lcl_dns_srv_fm_trust_dns_srv
$IPTABLES -A ext_if_in -p udp --sport domain --dport $UNPRIVPORTS -j lcl_dns_srv_fm_trust_dns_srv
$IPTABLES -A ext_if_in -p udp --sport domain-s --dport $UNPRIVPORTS -j lcl_dns_srv_fm_trust_dns_srv

# Set up the jump to the chains for TCP requests
$IPTABLES -A ext_if_out -p tcp --sport $UNPRIVPORTS --dport domain -j lcl_dns_srv_to_trust_dns_srv
$IPTABLES -A ext_if_in -p tcp ! --syn --sport domain --dport $UNPRIVPORTS -j lcl_dns_srv_fm_trust_dns_srv
$IPTABLES -A ext_if_out -p tcp --sport $UNPRIVPORTS --dport domain-s -j lcl_dns_srv_to_trust_dns_srv
$IPTABLES -A ext_if_in -p tcp ! --syn --sport domain-s --dport $UNPRIVPORTS -j lcl_dns_srv_fm_trust_dns_srv

####################
# Set up the rules #
####################
# Add the rules for DNS requests/reponses going to trusted DNS servers
# from the firewall
$IPTABLES -A lcl_dns_srv_to_trust_dns_srv -d $NAMESERVER_1 -j ACCEPT
$IPTABLES -A lcl_dns_srv_to_trust_dns_srv -d $NAMESERVER_2 -j ACCEPT
$IPTABLES -A lcl_dns_srv_to_trust_dns_srv -d $NAMESERVER_3 -j ACCEPT
$IPTABLES -A lcl_dns_srv_to_trust_dns_srv -d $NAMESERVER_4 -j ACCEPT
$IPTABLES -A lcl_dns_srv_to_trust_dns_srv -d $CLOUDFLARE_DNS_SERVER -j ACCEPT
$IPTABLES -A lcl_dns_srv_fm_trust_dns_srv -s $NAMESERVER_1 -j ACCEPT
$IPTABLES -A lcl_dns_srv_fm_trust_dns_srv -s $NAMESERVER_2 -j ACCEPT
$IPTABLES -A lcl_dns_srv_fm_trust_dns_srv -s $NAMESERVER_3 -j ACCEPT
$IPTABLES -A lcl_dns_srv_fm_trust_dns_srv -s $NAMESERVER_4 -j ACCEPT
$IPTABLES -A lcl_dns_srv_fm_trust_dns_srv -s $CLOUDFLARE_DNS_SERVER -j ACCEPT

###############################################################
# Domain Name Server - DNS (LAN machines making queries to the
# local DNS server or one of the remote trusted servers)
###############################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "DNS (LAN-to-local), "
fi

#####################
# Set up the chains #
#####################
# Chains for UDP requests
$IPTABLES -A lan_if_out -p udp --sport domain --dport $UNPRIVPORTS -j trusted_dns_srv_LAN_response
$IPTABLES -A lan_if_out -p udp --sport domain-s --dport $UNPRIVPORTS -j trusted_dns_srv_LAN_response
$IPTABLES -A lan_if_out -p udp --sport $MULTICAST_DNS --dport $MULTICAST_DNS -j trusted_dns_srv_LAN_response
$IPTABLES -A lan_if_multi_out -p udp --sport $MULTICAST_DNS --dport $MULTICAST_DNS -j ACCEPT
$IPTABLES -A lan_if_in -p udp --sport $UNPRIVPORTS --dport domain -j trusted_dns_srv_LAN_query
$IPTABLES -A lan_if_in -p udp --sport $UNPRIVPORTS --dport domain-s -j trusted_dns_srv_LAN_query
$IPTABLES -A lan_if_in -p udp --sport $MULTICAST_DNS --dport $MULTICAST_DNS -j trusted_dns_srv_LAN_query
$IPTABLES -A lan_if_in -p udp -d $BROADCAST_DEST --dport $UNPRIVPORTS --sport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A lan_if_in -p udp -d $INTERNAL_BROADCAST_DEST --dport $UNPRIVPORTS --sport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A lan_if_multi_in -p udp --sport $MULTICAST_DNS --dport $MULTICAST_DNS -j ACCEPT
$IPTABLES -A ext_if_lan_out -p udp --sport domain --dport $UNPRIVPORTS -j trusted_dns_srv_LAN_response
$IPTABLES -A ext_if_lan_out -p udp --sport domain-s --dport $UNPRIVPORTS -j trusted_dns_srv_LAN_response
$IPTABLES -A ext_if_lan_out -p udp --sport $MULTICAST_DNS --dport $MULTICAST_DNS -j trusted_dns_srv_LAN_response
$IPTABLES -A ext_if_lan_in -p udp --sport $UNPRIVPORTS --dport domain -j trusted_dns_srv_LAN_query
$IPTABLES -A ext_if_lan_in -p udp --sport $UNPRIVPORTS --dport domain-s -j trusted_dns_srv_LAN_query
$IPTABLES -A ext_int -p udp --sport domain --dport $UNPRIVPORTS -j trusted_dns_srv_LAN_response
$IPTABLES -A ext_int -p udp --sport $MULTICAST_DNS --dport $MULTICAST_DNS -j trusted_dns_srv_LAN_response
$IPTABLES -A int_ext -p udp --sport $UNPRIVPORTS --dport domain -j trusted_dns_srv_LAN_query
$IPTABLES -A int_ext -p udp --sport $UNPRIVPORTS --dport domain-s -j trusted_dns_srv_LAN_query
$IPTABLES -A int_ext -p udp --sport $MULTICAST_DNS --dport $MULTICAST_DNS -j trusted_dns_srv_LAN_query

# Chains for TCP requests
$IPTABLES -A lan_if_out -p tcp --sport domain --dport $UNPRIVPORTS -j trusted_dns_srv_LAN_response
$IPTABLES -A lan_if_in -p tcp --sport $UNPRIVPORTS --dport domain -j trusted_dns_srv_LAN_query
$IPTABLES -A ext_if_lan_out -p tcp --sport domain --dport $UNPRIVPORTS -j trusted_dns_srv_LAN_response
$IPTABLES -A ext_if_lan_in -p tcp --sport $UNPRIVPORTS --dport domain -j trusted_dns_srv_LAN_query
$IPTABLES -A lan_if_out -p tcp --sport domain-s --dport $UNPRIVPORTS -j trusted_dns_srv_LAN_response
$IPTABLES -A lan_if_in -p tcp --sport $UNPRIVPORTS --dport domain-s -j trusted_dns_srv_LAN_query
$IPTABLES -A ext_if_lan_out -p tcp --sport domain-s --dport $UNPRIVPORTS -j trusted_dns_srv_LAN_response
$IPTABLES -A ext_if_lan_in -p tcp --sport $UNPRIVPORTS --dport domain-s -j trusted_dns_srv_LAN_query
$IPTABLES -A ext_int -p tcp --sport domain --dport $UNPRIVPORTS -j trusted_dns_srv_LAN_response
$IPTABLES -A int_ext -p tcp --sport $UNPRIVPORTS --dport domain -j trusted_dns_srv_LAN_query
$IPTABLES -A ext_int -p tcp --sport domain-s --dport $UNPRIVPORTS -j trusted_dns_srv_LAN_response
$IPTABLES -A int_ext -p tcp --sport $UNPRIVPORTS --dport domain-s -j trusted_dns_srv_LAN_query

####################
# Set up the rules #
####################
# Add the rules for DNS requests going to trusted DNS servers
$IPTABLES -A trusted_dns_srv_LAN_query -d $LOCAL_NAMESERVER -j ACCEPT
$IPTABLES -A trusted_dns_srv_LAN_query -d $LOCAL_NAMESERVER_INT -j ACCEPT
$IPTABLES -A trusted_dns_srv_LAN_query -d $NAMESERVER_1 -j ACCEPT
$IPTABLES -A trusted_dns_srv_LAN_query -d $NAMESERVER_2 -j ACCEPT
$IPTABLES -A trusted_dns_srv_LAN_query -d $NAMESERVER_3 -j ACCEPT
$IPTABLES -A trusted_dns_srv_LAN_query -d $NAMESERVER_4 -j ACCEPT
$IPTABLES -A trusted_dns_srv_LAN_query -d $CLOUDFLARE_DNS_SERVER -j ACCEPT

# If we get to here in the trusted_dns_srv_LAN_query processing chain, but
# we have not matched a trusted DNS server, we have a rogue request from our
# server to an untrusted DNS server. I want to log that separately along with 
# some identifying info to find out what program is doing that.
#
$IPTABLES -A trusted_dns_srv_LAN_query -j LOG --log-uid --log-prefix "UNTRUSTED_DNS_QUERY_FROM_LAN "

# Add the rules for DNS reponses coming from trusted DNS servers
$IPTABLES -A trusted_dns_srv_LAN_response -s $LOCAL_NAMESERVER -j ACCEPT
$IPTABLES -A trusted_dns_srv_LAN_response -s $LOCAL_NAMESERVER_INT -j ACCEPT
$IPTABLES -A trusted_dns_srv_LAN_response -s $NAMESERVER_1 -j ACCEPT
$IPTABLES -A trusted_dns_srv_LAN_response -s $NAMESERVER_2 -j ACCEPT
$IPTABLES -A trusted_dns_srv_LAN_response -s $NAMESERVER_3 -j ACCEPT
$IPTABLES -A trusted_dns_srv_LAN_response -s $NAMESERVER_4 -j ACCEPT
$IPTABLES -A trusted_dns_srv_LAN_response -s $CLOUDFLARE_DNS_SERVER -j ACCEPT

#########################################################################################
# Domain Name Server - DNS (local DNS server making queries to 
# remote, untrusted DNS servers and remote, untrusted DNS servers
# giving responses to local DNS server)
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n " DNS (local-to-untrusted), "
fi

#####################
# Set up the chains #
#####################
# Set up the jump to the chains for UDP requests
$IPTABLES -A ext_if_out -p udp --sport $UNPRIVPORTS --dport domain -j rmt_dns_srv_query
$IPTABLES -A ext_if_out -p udp --sport $UNPRIVPORTS --dport domain-s -j rmt_dns_srv_query
$IPTABLES -A ext_if_in -p udp --sport domain --dport $UNPRIVPORTS -j rmt_dns_srv_response
$IPTABLES -A ext_if_in -p udp --sport domain-s --dport $UNPRIVPORTS -j rmt_dns_srv_response

# Set up the jump to the chains for TCP requests
$IPTABLES -A ext_if_out -p tcp --sport $UNPRIVPORTS --dport domain -j rmt_dns_srv_query
$IPTABLES -A ext_if_out -p tcp --sport $UNPRIVPORTS --dport domain-s -j rmt_dns_srv_query
$IPTABLES -A ext_if_in -p tcp ! --syn --sport domain --dport $UNPRIVPORTS -j rmt_dns_srv_response
$IPTABLES -A ext_if_in -p tcp ! --syn --sport domain-s --dport $UNPRIVPORTS -j rmt_dns_srv_response

####################
# Set up the rules #
####################
# Add the rules for DNS requests/reponses going to trusted DNS servers
$IPTABLES -A rmt_dns_srv_query -j ACCEPT
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A rmt_dns_srv_response -p udp -m state --state ESTABLISHED,RELATED -j ACCEPT
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
$IPTABLES -A ext_if_in -p udp --sport $UNPRIVPORTS --dport domain -j lcl_dns_srv_rmt_query
$IPTABLES -A ext_if_out -p udp --sport domain --dport $UNPRIVPORTS -j lcl_dns_srv_rmt_response
$IPTABLES -A ext_if_in -p udp --sport domain --dport domain -j lcl_dns_srv_rmt_query
$IPTABLES -A ext_if_out -p udp --sport domain --dport domain -j lcl_dns_srv_rmt_response
$IPTABLES -A ext_if_in -p udp --sport $UNPRIVPORTS --dport domain-s -j lcl_dns_srv_rmt_query
$IPTABLES -A ext_if_out -p udp --sport domain-s --dport $UNPRIVPORTS -j lcl_dns_srv_rmt_response
$IPTABLES -A ext_if_in -p udp --sport domain-s --dport domain-s -j lcl_dns_srv_rmt_query
$IPTABLES -A ext_if_out -p udp --sport domain-s --dport domain-s -j lcl_dns_srv_rmt_response

# Chains for TCP requests
$IPTABLES -A ext_if_in -p tcp --syn --sport $UNPRIVPORTS --dport domain -j lcl_dns_srv_rmt_query
$IPTABLES -A ext_if_out -p tcp --syn --sport domain --dport $UNPRIVPORTS -j lcl_dns_srv_rmt_response
$IPTABLES -A ext_if_in -p tcp --syn --sport $UNPRIVPORTS --dport domain-s -j lcl_dns_srv_rmt_query
$IPTABLES -A ext_if_out -p tcp --syn --sport domain-s --dport $UNPRIVPORTS -j lcl_dns_srv_rmt_response

####################
# Set up the rules #
####################
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
 # Add the rules for DNS requests from the Internet
	$IPTABLES -A lcl_dns_srv_rmt_query -d $LOCAL_NAMESERVER -m state --state NEW -j ACCEPT
fi
$IPTABLES -A lcl_dns_srv_rmt_query -d $LOCAL_NAMESERVER -j ACCEPT
$IPTABLES -A lcl_dns_srv_rmt_response -s $LOCAL_NAMESERVER -j ACCEPT


#########################################################################################
# Firewall and LAN TCP clients to remote TCP servers for those remote services that both
# the firewall and the LAN machines should be able to use. There will also likely
# be services (e.g., the DNS service above) that the firewall has access to that the
# LAN machines do not. There is also a separate set for UDP servers.
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "F/W & LAN TCP clients to Internet: "
fi

#####################
# Set up the chains #
#####################
# A TCP client on the firewall talking to remote server
$IPTABLES -A ext_if_out -p tcp --sport $UNPRIVPORTS -j lcl_tcp_client_request
$IPTABLES -A ext_if_in -p tcp ! --syn --dport $UNPRIVPORTS -j rmt_tcp_srv_response
# A TCP client on the LAN talking to a remote server
$IPTABLES -A int_ext -p tcp --sport $UNPRIVPORTS -j lcl_tcp_client_request
$IPTABLES -A ext_int -p tcp ! --syn --dport $UNPRIVPORTS -j rmt_tcp_srv_response

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
	$IPTABLES -A lcl_tcp_client_request -p tcp --dport ssh --syn -m state --state NEW -j ACCEPT
fi
$IPTABLES -A lcl_tcp_client_request -p tcp --dport ssh -j ACCEPT
$IPTABLES -A rmt_tcp_srv_response -p tcp ! --syn --sport ssh -j ACCEPT

# Client rules for HTTP, HTTPS, AUTH, and FTP control requests 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "http (80,81,8080,8443,2443,4885), https, whois, auth, "
	echo -n " FTP control, FTP data, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A lcl_tcp_client_request -p tcp -m multiport --destination-port http,whois,$WEB_ALT_PORT,$WEB_PROXY_PORT,$WEB_PROXY_PORT2,$WEB_ALT_HTTPS_PORT,$VT_ALT_HTTPS_PORT,https,auth,ftp,ftp-data,ftps,ftps-data,4885 --syn -m state --state NEW -j ACCEPT
fi
$IPTABLES -A lcl_tcp_client_request -p tcp -m multiport --destination-port http,$WEB_ALT_PORT,$WEB_PROXY_PORT,$WEB_PROXY_PORT2,$WEB_ALT_HTTPS_PORT,https,auth,ftp,ftp-data,ftps,ftps-data -j ACCEPT
$IPTABLES -A rmt_tcp_srv_response -p tcp -m multiport --source-port http,$WEB_ALT_PORT,$WEB_PROXY_PORT,$WEB_PROXY_PORT2,$WEB_ALT_HTTPS_PORT,https,auth,ftp,ftp-data,ftps,ftps-data -j ACCEPT
$IPTABLES -A rmt_tcp_srv_response -p udp --source-port https -j ACCEPT
$IPTABLES -A rmt_tcp_srv_response -p tcp --sport ftp-data -j ACCEPT
$IPTABLES -A rmt_tcp_srv_response -p tcp --sport ftps-data -j ACCEPT

# POP3 and IMAP2 client
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "POP3, IMAP2, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A lcl_tcp_client_request -p tcp -m multiport --destination-port pop3,imap2 --syn -m state --state NEW -j ACCEPT
fi
$IPTABLES -A lcl_tcp_client_request -p tcp -m multiport --destination-port pop3,imap2 -j ACCEPT
$IPTABLES -A rmt_tcp_srv_response -p tcp -m multiport --source-port pop3,imap2 ! --syn -j ACCEPT

# Secure POP client
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "pop3s, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A lcl_tcp_client_request -p tcp --dport pop3s --syn -m state --state NEW -j ACCEPT
fi
$IPTABLES -A lcl_tcp_client_request -p tcp --dport pop3s -j ACCEPT
$IPTABLES -A rmt_tcp_srv_response -p tcp ! --syn --sport pop3s -j ACCEPT

# Secure IMAP client
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "imaps, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A lcl_tcp_client_request -p tcp --dport imaps --syn -m state --state NEW -j ACCEPT
fi
$IPTABLES -A lcl_tcp_client_request -p tcp --dport imaps -j ACCEPT
$IPTABLES -A rmt_tcp_srv_response -p tcp ! --syn --sport imaps -j ACCEPT

# SMTP mail client
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "smtp, smtps, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A lcl_tcp_client_request -p tcp -d $REMOTE_SMTP_SERVER --dport smtp --syn -m state --state NEW -j ACCEPT
fi
$IPTABLES -A lcl_tcp_client_request -p tcp -d $REMOTE_SMTP_SERVER --dport smtp -j ACCEPT
$IPTABLES -A rmt_tcp_srv_response -p tcp ! --syn -s $REMOTE_SMTP_SERVER --sport smtp -j ACCEPT
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A lcl_tcp_client_request -p tcp -d $REMOTE_SMTP_SERVER --dport smtps --syn -m state --state NEW -j ACCEPT
fi
$IPTABLES -A lcl_tcp_client_request -p tcp -d $REMOTE_SMTP_SERVER --dport smtps -j ACCEPT
$IPTABLES -A rmt_tcp_srv_response -p tcp ! --syn -s $REMOTE_SMTP_SERVER --sport smtps -j ACCEPT
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A lcl_tcp_client_request -p tcp -d $REMOTE_SMTP_SERVER --dport $ALT_SMTPS_PORT --syn -m state --state NEW -j ACCEPT
fi
$IPTABLES -A lcl_tcp_client_request -p tcp -d $REMOTE_SMTP_SERVER --dport $ALT_SMTPS_PORT -j ACCEPT
$IPTABLES -A rmt_tcp_srv_response -p tcp ! --syn -s $REMOTE_SMTP_SERVER --sport $ALT_SMTPS_PORT -j ACCEPT

# SNMP (requires UDP connections as well)
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "SNMP, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A lcl_tcp_client_request -p tcp -d $NEWS_SERVER --dport snmp --syn -m state --state NEW -j ACCEPT
fi
$IPTABLES -A lcl_tcp_client_request -p tcp -d $NEWS_SERVER --dport snmp -j ACCEPT
$IPTABLES -A rmt_tcp_srv_response -p tcp ! --syn -s $NEWS_SERVER --sport snmp -j ACCEPT

# Usenet news client
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& Usenet News, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A lcl_tcp_client_request -p tcp -d $NEWS_SERVER --dport nntp --syn -m state --state NEW -j ACCEPT
fi
$IPTABLES -A lcl_tcp_client_request -p tcp -d $NEWS_SERVER --dport nntp -j ACCEPT
$IPTABLES -A rmt_tcp_srv_response -p tcp ! --syn -s $NEWS_SERVER --sport nntp -j ACCEPT
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A lcl_tcp_client_request -p tcp -d $NEWS_SERVER --dport nntps --syn -m state --state NEW -j ACCEPT
fi
$IPTABLES -A lcl_tcp_client_request -p tcp -d $NEWS_SERVER --dport nntps -j ACCEPT
$IPTABLES -A rmt_tcp_srv_response -p tcp ! --syn -s $NEWS_SERVER --sport nntps -j ACCEPT


#########################################################################################
# Internal LAN UDP clients to services that appear on the firewall machine (whether 
# that's where they truly are or not) There is also a separate set for UDP servers.
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "LAN UDP clts->Local svcs: "
fi
# A UDP client on the LAN talking to a local server on the internal inteface
$IPTABLES -A lan_if_in -p udp -s $LAN_SUBNET --sport $UNPRIVPORTS -j LAN_udp_client_request
$IPTABLES -A lan_if_out -p udp --dport $UNPRIVPORTS -j udp_srv_LAN_response
$IPTABLES -A lan_if_in -p udp -s $LAN_SUBNET --sport $MULTICAST_DNS -j LAN_udp_client_request
$IPTABLES -A lan_if_out -p udp --dport $MULTICAST_DNS -j udp_srv_LAN_response

# Multicast DNS
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Multicast DNS "
fi
$IPTABLES -A LAN_udp_client_request -p udp --dport $MULTICAST_DNS -j ACCEPT
$IPTABLES -A udp_srv_LAN_response -p udp --sport $MULTICAST_DNS -j ACCEPT

# Some authentication servers
$IPTABLES -A LAN_udp_client_request -p udp --destination-port https -j ACCEPT
$IPTABLES -A udp_srv_LAN_response -p udp --source-port https -j ACCEPT

# Internal Network Broadcasts
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& broadcasts."
fi
$IPTABLES -A LAN_udp_client_request -p udp -d $BROADCAST_DEST -j ACCEPT
$IPTABLES -A LAN_udp_client_request -p udp -d $INTERNAL_BROADCAST_DEST -j ACCEPT

#########################################################################################
# Internal LAN TCP clients to services that appear on the firewall machine (whether 
# that's where they truly are or not) There is also a separate set for UDP servers.
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "LAN TCP clts->F/W svcs: "
fi
#####################
# Set up the chains #
#####################
# A TCP client on the LAN talking to a local server on the internal interface
$IPTABLES -A lan_if_in -p tcp -s $LAN_SUBNET --sport $UNPRIVPORTS -j LAN_tcp_client_request
$IPTABLES -A lan_if_out -p tcp ! --syn -d $LAN_SUBNET --dport $UNPRIVPORTS -j tcp_srv_LAN_response
# special rule to allow ssh to new server machine at its temp IP addr
$IPTABLES -A lan_if_out -p tcp -s $LAN_IP --sport $UNPRIVPORTS -d $LAN_SUBNET --dport ssh -j ACCEPT
# A TCP client on the LAN talking to a local server on the external interface via the
# FORWARD chain. (This should be considered "differently" than requests on the public
# IP from the INPUT chain
$IPTABLES -A ext_if_lan_in -p tcp -s $LAN_SUBNET --sport $UNPRIVPORTS -j LAN_tcp_client_request
$IPTABLES -A ext_if_lan_out -p tcp ! --syn -d $LAN_SUBNET --dport $UNPRIVPORTS -j tcp_srv_LAN_response

####################
# Set up the rules #
####################
# SSH client talking using SSL to any remote SSH server daemon
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "SSH, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A LAN_tcp_client_request -p tcp --dport ssh --syn -m state --state NEW -j ACCEPT
fi
$IPTABLES -A LAN_tcp_client_request -p tcp --dport ssh -j ACCEPT
$IPTABLES -A tcp_srv_LAN_response -p tcp ! --syn --sport ssh -j ACCEPT

# Client rules for HTTP, HTTPS, & AUTH requests 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "HTTP, HTTPS, AUTH "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A LAN_tcp_client_request -p tcp -m multiport --destination-port http,https,auth --syn -m state --state NEW -j ACCEPT
fi
$IPTABLES -A LAN_tcp_client_request -p tcp -m multiport --destination-port http,https,auth -j ACCEPT
$IPTABLES -A tcp_srv_LAN_response -p tcp -m multiport --source-port http,https,auth ! --syn -j ACCEPT


# Internal Network Broadcasts
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& broadcasts."
fi
$IPTABLES -A LAN_tcp_client_request -p tcp -d $BROADCAST_DEST -j ACCEPT
$IPTABLES -A LAN_tcp_client_request -p tcp -d $INTERNAL_BROADCAST_DEST -j ACCEPT


#########################################################################################
# A remote (potentially) untrusted internet client talking to a Local TCP server.
# There is also a separate set for UDP servers.
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Internet TCP clts->F/W svcs: "
fi

#####################
# Set up the chains #
#####################
$IPTABLES -A ext_if_in -p tcp --sport $UNPRIVPORTS -j rmt_tcp_client_request
$IPTABLES -A ext_if_out -p tcp ! --syn --dport $UNPRIVPORTS -j lcl_tcp_srv_response

####################
# Set up the rules #
####################
# Incoming SSH server requests
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "SSH "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A rmt_tcp_client_request -p tcp --dport $MY_SSH_PORT -m state --state NEW -j ACCEPT
fi
$IPTABLES -A rmt_tcp_client_request -p tcp --dport $MY_SSH_PORT -j ACCEPT
$IPTABLES -A lcl_tcp_srv_response -p tcp ! --syn --sport $MY_SSH_PORT -j ACCEPT


#########################################################################################
# Firewall and LAN UDP clients to remote UDP servers for those remote services that both
# the firewall and the LAN machines should be able to use. There will also likely
# be services (e.g., the DNS service above) that the firewall has access to that the
# LAN machines do not. There is also a separate set for TCP servers.
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "F/W & LAN UDP clts->Internet: "
fi

#####################
# Set up the chains #
#####################
# A UDP client on the firewall talking to remote server
$IPTABLES -A ext_if_out -p udp -j local_udp_client_request
$IPTABLES -A ext_if_in -p udp -j remote_udp_srv_response
# A UDP client on the LAN talking to a remote server
$IPTABLES -A int_ext -p udp -j local_udp_client_request
$IPTABLES -A ext_int -p udp -j remote_udp_srv_response

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
	$IPTABLES -A local_udp_client_request -p udp --sport ntp --dport ntp -m state --state NEW -j ACCEPT
fi
$IPTABLES -A local_udp_client_request -p udp --sport $UNPRIVPORTS --dport ntp -j ACCEPT
$IPTABLES -A remote_udp_srv_response -p udp --sport ntp --dport $UNPRIVPORTS -j ACCEPT

# SNMP - Current rule allows LAN and firewall to SNMP with any IP addr.
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "SNMP, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A local_udp_client_request -p udp --sport $UNPRIVPORTS --dport snmp:snmptrap -m state --state NEW -j ACCEPT
fi
$IPTABLES -A local_udp_client_request -p udp --sport $UNPRIVPORTS --dport snmp:snmptrap -j ACCEPT
$IPTABLES -A remote_udp_srv_response -p udp --sport snmp:snmptrap --dport $UNPRIVPORTS -j ACCEPT

# HTTPS - used by virtually every website today
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "https, "
fi
$IPTABLES -A local_udp_client_request -p udp --sport $UNPRIVPORTS --destination-port https -j ACCEPT

# Traceroute - Current rule allows LAN and firewall to traceroute to any IP addr.
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "traceroute, "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A local_udp_client_request -p udp --sport $TRACEROUTE_SRC_PORTS --dport $TRACEROUTE_DEST_PORTS -m state --state NEW -j ACCEPT
fi
$IPTABLES -A local_udp_client_request -p udp --sport $TRACEROUTE_SRC_PORTS --dport $TRACEROUTE_DEST_PORTS -j ACCEPT
$IPTABLES -A remote_udp_srv_response -p udp --sport $TRACEROUTE_DEST_PORTS --dport $TRACEROUTE_SRC_PORTS -j ACCEPT

# Multicast DNS
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& Mutlicast DNS "
fi
$IPTABLES -A local_udp_client_request -p udp --dport $MULTICAST_DNS -j ACCEPT
$IPTABLES -A remote_udp_srv_response -p udp --sport $MULTICAST_DNS -j ACCEPT


#########################################################################################
# The firewall machine originating UDP requests to the Internal LAN UDP machines.
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "UDP F/W - Local Lan: "
fi
#####################
# Set up the chains #
#####################
$IPTABLES -A lan_if_out -p udp -j LAN_udp_firewall_request
$IPTABLES -A lan_if_in -p udp -j LAN_udp_firewall_response

####################
# Set up the rules #
####################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "CUPS printer ctrl "
fi
# Printer, scanner, copier
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A LAN_udp_firewall_request -p udp -s $LAN_IP --sport $UNPRIVPORTS -d $PRINTER --dport $PRINTER_CTRL_PORT1 -m state --state NEW -j ACCEPT
fi
$IPTABLES -A LAN_udp_firewall_request -p udp -s $LAN_IP --sport $UNPRIVPORTS -d $PRINTER --dport $PRINTER_CTRL_PORT1 -j ACCEPT
$IPTABLES -A LAN_udp_firewall_response -p udp -s $PRINTER --sport $PRINTER_CTRL_PORT1 -d $LAN_IP --dport $UNPRIVPORTS -j ACCEPT
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A LAN_udp_firewall_request -p udp --sport $UNPRIVPORTS -d $PRINTER --dport $PRINTER_CTRL_PORT2 -m state --state NEW -j ACCEPT
fi
$IPTABLES -A LAN_udp_firewall_request -p udp --sport $UNPRIVPORTS -d $PRINTER --dport $PRINTER_CTRL_PORT2 -j ACCEPT
$IPTABLES -A LAN_udp_firewall_response -p udp -s $PRINTER --sport $PRINTER_CTRL_PORT2 --dport $UNPRIVPORTS -j ACCEPT


#########################################################################################
# The firewall machine originating TCP requests to the Internal LAN UDP machines.
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "TCP F/W - Local Lan: "
fi

#####################
# Set up the chains #
#####################
$IPTABLES -A lan_if_out -p tcp -j LAN_tcp_firewall_request
$IPTABLES -A lan_if_in -p tcp -j LAN_tcp_firewall_response

####################
# Set up the rules #
####################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "CUPS printer ctrl "
fi
# Printer, Scanner, Copier, Fax
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A LAN_tcp_firewall_request -p tcp -s $LAN_IP --sport $UNPRIVPORTS -d $PRINTER --dport $PRINTER_TCP_PRINTING -m state --state NEW -j ACCEPT
fi
$IPTABLES -A LAN_tcp_firewall_request -p tcp -s $LAN_IP --sport $UNPRIVPORTS -d $PRINTER --dport $PRINTER_TCP_PRINTING -j ACCEPT
$IPTABLES -A LAN_tcp_firewall_response -p tcp -s $PRINTER --sport $PRINTER_TCP_PRINTING -d $LAN_IP --dport $UNPRIVPORTS -j ACCEPT


#########################################################################################
# A remote (potentially) untrusted internet client talking to a Local UDP server.
# There is also a separate set for TCP servers.
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "UDP F/W - Internet: "
fi

#####################
# Set up the chains #
#####################
$IPTABLES -A ext_if_in -p udp --sport $UNPRIVPORTS -j remote_udp_client_request
$IPTABLES -A ext_if_out -p udp --dport $UNPRIVPORTS -j local_udp_srv_response

####################
# Set up the rules #
####################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "traceroute."
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A remote_udp_client_request -p udp --sport $TRACEROUTE_SRC_PORTS --dport $TRACEROUTE_DEST_PORTS -m state --state NEW -j ACCEPT
fi
$IPTABLES -A remote_udp_client_request -p udp --sport $TRACEROUTE_SRC_PORTS --dport $TRACEROUTE_DEST_PORTS -j ACCEPT
$IPTABLES -A local_udp_srv_response -p udp --sport $TRACEROUTE_DEST_PORTS --dport $TRACEROUTE_SRC_PORTS -j ACCEPT


#########################################################################################
# ICMP requests to and from the firewall machine from the Internet
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ICMP F/W - Internet: "
fi

#####################
# Set up the chains #
#####################
$IPTABLES -A ext_if_in -p icmp -j ext_if_icmp_in
$IPTABLES -A ext_if_out -p icmp -j ext_if_icmp_out

####################
# Set up the rules #
####################
# Log and drop initial ICMP fragments
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "frag drop, "
fi
$IPTABLES -A ext_if_icmp_in --fragment -j LOG --log-prefix "(D)Fragmented incoming ICMP: "
$IPTABLES -A ext_if_icmp_in --fragment -j DROP
$IPTABLES -A ext_if_icmp_out --fragment -j LOG --log-prefix "(D)Fragmented outgoing ICMP: "
$IPTABLES -A ext_if_icmp_out --fragment -j DROP

# Outgoing ping 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ping (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A ext_if_icmp_out -p icmp --icmp-type echo-request -m state --state NEW -j ACCEPT
fi
$IPTABLES -A ext_if_icmp_out -p icmp --icmp-type echo-request -j ACCEPT
$IPTABLES -A ext_if_icmp_in -p icmp --icmp-type echo-reply -j ACCEPT

# Incoming ping
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ping (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A ext_if_icmp_in -p icmp -s $INTERNET_SUBNET --icmp-type echo-request -m state --state NEW -j ACCEPT
fi
$IPTABLES -A ext_if_icmp_in -p icmp --icmp-type echo-request -s $INTERNET_SUBNET -j ACCEPT
$IPTABLES -A ext_if_icmp_out -p icmp --icmp-type echo-reply -d $INTERNET_SUBNET -j ACCEPT

# Destination Unreachable Type 3 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "dest unreachable, "
fi
$IPTABLES -A ext_if_icmp_out -p icmp --icmp-type fragmentation-needed -j ACCEPT
$IPTABLES -A ext_if_icmp_in -p icmp --icmp-type destination-unreachable -j ACCEPT

# Parameter Problem 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n " parm problem, "
fi
$IPTABLES -A ext_if_icmp_out -p icmp --icmp-type parameter-problem -j ACCEPT
$IPTABLES -A ext_if_icmp_in -p icmp --icmp-type parameter-problem -j ACCEPT

# Time Exceeded
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "time exceeded, "
fi
$IPTABLES -A ext_if_icmp_in -p icmp --icmp-type time-exceeded -j ACCEPT

# Source Quench 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& source quench."
fi
$IPTABLES -A ext_if_icmp_out -p icmp --icmp-type source-quench -j ACCEPT
$IPTABLES -A ext_if_icmp_in -p icmp --icmp-type source-quench -j ACCEPT

#########################################################################################
# ICMP requests to and from the internal LAN to both the internal interface and the
# external interface. (We treat requests from the internal machines the same way 
# regardless of which interface they hit.)
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ICMP LAN - F/W: "
fi

#####################
# Set up the chains #
#####################
$IPTABLES -A lan_if_in -p icmp -j lan_if_icmp_in
$IPTABLES -A ext_if_lan_in -p icmp -j lan_if_icmp_in
$IPTABLES -A lan_if_out -p icmp -j lan_if_icmp_out
$IPTABLES -A ext_if_lan_out -p icmp -j lan_if_icmp_out

####################
# Set up the rules #
####################
# Log and drop initial ICMP fragments
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "frag drop, "
fi
$IPTABLES -A lan_if_icmp_in --fragment -j LOG --log-prefix "(D)Fragmented incoming ICMP: "
$IPTABLES -A lan_if_icmp_in --fragment -j DROP
$IPTABLES -A lan_if_icmp_out --fragment -j LOG --log-prefix "(D)Fragmented outgoing ICMP: "
$IPTABLES -A lan_if_icmp_out --fragment -j DROP

# Outgoing ping
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ping (out), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A lan_if_icmp_out -p icmp --icmp-type echo-request -m state --state NEW -j ACCEPT
fi
$IPTABLES -A lan_if_icmp_out -p icmp --icmp-type echo-request -j ACCEPT
$IPTABLES -A lan_if_icmp_in -p icmp --icmp-type echo-reply -j ACCEPT

# Incoming ping
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ping (in), "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A lan_if_icmp_in -p icmp -s $LAN_SUBNET --icmp-type echo-request -m state --state NEW -j ACCEPT
fi
$IPTABLES -A lan_if_icmp_in -p icmp --icmp-type echo-request -s $LAN_SUBNET -j ACCEPT
$IPTABLES -A lan_if_icmp_out -p icmp --icmp-type echo-reply -d $LAN_SUBNET -j ACCEPT

# Destination Unreachable Type 3 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "dest unreachable, "
fi
$IPTABLES -A lan_if_icmp_out -p icmp --icmp-type fragmentation-needed -j ACCEPT
$IPTABLES -A lan_if_icmp_in -p icmp --icmp-type destination-unreachable -j ACCEPT

# Parameter Problem 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n " parm problem, "
fi
$IPTABLES -A lan_if_icmp_out -p icmp --icmp-type parameter-problem -j ACCEPT
$IPTABLES -A lan_if_icmp_in -p icmp --icmp-type parameter-problem -j ACCEPT

# Time Exceeded
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "time exceeded, "
fi
$IPTABLES -A lan_if_icmp_in -p icmp --icmp-type time-exceeded -j ACCEPT

# Source Quench 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& source quench."
fi
$IPTABLES -A lan_if_icmp_out -p icmp --icmp-type source-quench -j ACCEPT
$IPTABLES -A lan_if_icmp_in -p icmp --icmp-type source-quench -j ACCEPT

#########################################################################################
# ICMP requests to and from the internal LAN to destinations on the Internet. Although
# we have no objections to LAN machines pinging remote hosts, we don't allow the
# reverse to occur
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ICMP LAN - Internet: "
fi

#####################
# Set up the chains #
#####################
$IPTABLES -A ext_int -p icmp -j ext_int_icmp
$IPTABLES -A int_ext -p icmp -j int_ext_icmp

####################
# Set up the rules #
####################
# Log and drop initial ICMP fragments
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "frag drop, "
fi
$IPTABLES -A ext_int_icmp --fragment -j LOG --log-prefix "(D)Fragmented incoming ICMP: "
$IPTABLES -A ext_int_icmp --fragment -j DROP
$IPTABLES -A int_ext_icmp --fragment -j LOG --log-prefix "(D)Fragmented outgoing ICMP: "
$IPTABLES -A int_ext_icmp --fragment -j DROP

# Outgoing ping & incoming reply
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& ping (out)."
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A int_ext_icmp -p icmp --icmp-type echo-request -m state --state NEW -j ACCEPT
fi
$IPTABLES -A int_ext_icmp -p icmp --icmp-type echo-request -j ACCEPT
$IPTABLES -A ext_int_icmp -p icmp --icmp-type echo-reply -j ACCEPT


#########################################################################################
# Specific rules for VPN and services
#########################################################################################

if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Establishing services for VPN: "
fi

#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on VPN machine
$IPTABLES -A int_ext -s $VPN_TUNNEL -j vpn_machine_out
$IPTABLES -A ext_int -d $VPN_TUNNEL -j vpn_machine_in

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
VPN_SUBNET="21.121.121.21" # VPN nework IP (work-dev)
VPN2_IP="21.121.118.51" # VPN nework IP (work-staging)
VPN3_IP="21.121.117.25" # VPN nework IP (work-prod)

# VPN service
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "VPN, "
fi
$IPTABLES -A vpn_machine_out -p esp -j ACCEPT
$IPTABLES -A vpn_machine_out -p udp --sport isakmp --dport isakmp -j ACCEPT
$IPTABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS --dport $VPN_SERVICE_TCP_PORT -j ACCEPT
$IPTABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS --dport $VPN_SERVICE_TCP_PORT_RNG -j ACCEPT
$IPTABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS --dport $VPN_SERVICE3_TCP_PORT_RNG -j ACCEPT
$IPTABLES -A vpn_machine_out -p 47 -j ACCEPT
$IPTABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS --dport $VPN_SERVICE2_UDP_PORT -j ACCEPT
$IPTABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS --dport $VPN_SERVICE3_UDP_PORT2 -j ACCEPT
$IPTABLES -A vpn_machine_out -p udp --sport $VPN_SERVICE3_UDP_PORT --dport $VPN_SERVICE3_UDP_PORT -j ACCEPT
$IPTABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS --dport $VPN_SERVICE3_UDP_PORT_RNG -j ACCEPT
$IPTABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS -d $VPN2_IP --dport isakmp -j ACCEPT
$IPTABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS -d $VPN3_IP --dport isakmp -j ACCEPT
$IPTABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS --dport domain -j ACCEPT
$IPTABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS -d $VPN2_IP --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS -d $VPN3_IP --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A vpn_machine_out -p udp --sport $UNPRIVPORTS --dport isakmp -j ACCEPT
$IPTABLES -A vpn_machine_out -p udp --sport $VPN_SERVICE_UDP_PORT --dport $VPN_SERVICE_UDP_PORT -j ACCEPT
$IPTABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS -d $VPN_SUBNET --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS -d $VPN2_IP --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS -d $VPN3_IP --dport $VPN_SERVICE3_TCP_PORT -j ACCEPT
$IPTABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS --dport $VPN_SERVICE3_TCP_PORT2 -j ACCEPT
$IPTABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS --dport $VPN_SERVICE3_TCP_PORT3_RNG -j ACCEPT
$IPTABLES -A vpn_machine_out -p tcp --sport $UNPRIVPORTS --dport $VPN_SERVICE3_TCP_PORT4 -j ACCEPT

$IPTABLES -A vpn_machine_in -p esp -j ACCEPT
$IPTABLES -A vpn_machine_in -p udp --sport isakmp --dport isakmp -j ACCEPT
$IPTABLES -A vpn_machine_in -p udp --sport $VPN_SERVICE_UDP_PORT --dport $VPN_SERVICE_UDP_PORT -j ACCEPT

# mail via SSH tunnels
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& mail tunnels "
fi
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
	$IPTABLES -A vpn_machine_out -p tcp --dport $VPN_CLIENT_MAIL_PORTS -m state --state NEW -j ACCEPT
fi
$IPTABLES -A vpn_machine_out -p tcp --dport $VPN_CLIENT_MAIL_PORTS -j ACCEPT
$IPTABLES -A vpn_machine_in -p tcp ! --syn --sport $VPN_CLIENT_MAIL_PORTS -j ACCEPT


#########################################################################################
# Rules for guest gaming desktop
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Establishing rules for guest gaming PC: "
fi

#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on 
$IPTABLES -A int_ext -s $GUESTGAMER -j guest_gamer_out
$IPTABLES -A ext_int -d $GUESTGAMER -j guest_gamer_in

####################
# Set up the rules #
####################


####################
# Guild Wars 2, Wildstar, Rift 
####################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Guild Wars 2, "
fi
# Constants 
GW2_TCP_PORT1="6112"
GW2_TCP_PORT2="6600"
$IPTABLES -A guest_gamer_out -p tcp --sport $GW2_TCP_PORT1 --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A guest_gamer_out -p tcp --sport $GW2_TCP_PORT2 --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS --dport $GW2_TCP_PORT1 -j ACCEPT
$IPTABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS --dport $GW2_TCP_PORT2 -j ACCEPT
$IPTABLES -A guest_gamer_in -p tcp --sport $UNPRIVPORTS --dport $GW2_TCP_PORT1 -j ACCEPT
$IPTABLES -A guest_gamer_in -p tcp --sport $UNPRIVPORTS --dport $GW2_TCP_PORT2 -j ACCEPT
IRC_TCP_PORT_RNG1="6660:6669"
IRC_TCP_PORT_RNG2="5000:5009"
$IPTABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS --dport $IRC_TCP_PORT_RNG1 -j ACCEPT
$IPTABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS --dport $IRC_TCP_PORT_RNG2 -j ACCEPT

##############################
# League of Legends
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "LoL, "
fi

LOL_UDP_PORT1="8088"
LOL_UDP_PORT_RNG1="5000:5500"
LOL_TCP_PORT_RNG1="8393:8400"
LOL_TCP_PORT_LIST1="5222,5223,2099,8088"
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS --dport $LOL_UDP_PORT_RNG1 -j ACCEPT
$IPTABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS --dport $LOL_TCP_PORT_RNG1 -j ACCEPT
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS --dport $LOL_UDP_PORT1 -j ACCEPT
$IPTABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS -m multiport --dports $LOL_TCP_PORT_LIST1 -j ACCEPT

if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n " Payday 2, "
fi
# Limit of 15 ports in a multiport list 
PAYDAY2_UDP_PORT_LIST1="9899,27017,60071"
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS -m multiport --dports $PAYDAY2_UDP_PORT_LIST1 -j ACCEPT

##############################
# Roblox
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Roblox, "
fi

ROBLOX_UDP_PORT_RNG="49152:65535"
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS --dport $ROBLOX_UDP_PORT_RNG -j ACCEPT
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS 

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
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS --dport $KF_GAME_UDP_PORT -j ACCEPT
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS --dport $KF_QUERY_UDP_PORT -j ACCEPT
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS --dport $KF2_GAME_TCP_UDP_PORT -j ACCEPT
$IPTABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS --dport $KF2_GAME_TCP_UDP_PORT -j ACCEPT
$IPTABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS --dport $KF_WEBADMIN_TCP_PORT -j ACCEPT
$IPTABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS --dport $KF2_WEBADMIN_TCP_PORT -j ACCEPT
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS --dport $GAMESPY_QUERY_UDP_PORT_RNG -j ACCEPT
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS --dport $STEAM_UDP_PORT -j ACCEPT
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS --dport $KF_MASTER_SVR_UDP_PORT -j ACCEPT
$IPTABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS --dport $KF_MASTER_SVR_TCP_PORT -j ACCEPT
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS --dport $KF2_MASTER_SVR_TCP_UDP_PORT -j ACCEPT
$IPTABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS --dport $KF2_MASTER_SVR_TCP_UDP_PORT -j ACCEPT

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
$IPTABLES -A guest_gamer_out -p udp --sport $STEAM_SVR_SEARCH_UDP_PORT2 --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS --dport $STEAM_FRIENDS_UDP_PORT -j ACCEPT
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS --dport $STEAM_UDP_PORT_RNG -j ACCEPT
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS --dport $STEAM_UDP_PORT_RNG2 -j ACCEPT
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS --dport $STEAM_UDP_PORT_RNG3 -j ACCEPT
$IPTABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS --dport $STEAM_TCP_PORT_RNG -j ACCEPT
$IPTABLES -A guest_gamer_out -p tcp --sport $UNPRIVPORTS --dport $STEAM_TCP_CROSS_CONNECT_PORT -j ACCEPT
$IPTABLES -A guest_gamer_out -p udp --sport $UNPRIVPORTS --dport $STEAM_DED_SVR_UDP_PORT1 -j ACCEPT
$IPTABLES -A guest_gamer_in -p udp --sport $STEAM_UDP_SRC_PORT --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A guest_gamer_in -p udp --sport $UNPRIVPORTS --dport $STEAM_DED_SVR_UDP_PORT1 -j ACCEPT
$IPTABLES -A guest_gamer_in -p udp --sport $UNPRIVPORTS --dport $STEAM_DED_SVR_UDP_PORT2 -j ACCEPT


#########################################################################################
# Amazon and Kasa devices
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Establishing rules for Amazon and Kasa devices: "
fi

#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on Amazon and Kasa smart plugs and switches
$IPTABLES -A int_ext -s $FRONTLIGHTS -j smartplugswitch_out
$IPTABLES -A ext_int -d $FRONTLIGHTS -j smartplugswitch_in
## Note this is not a complete list, but we don't have rules for the switches and 
## plugs .. yet

####################
# Set up the rules #
####################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Default rules only "
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
$IPTABLES -A int_ext -s $PRINTER -j network_printer_out
$IPTABLES -A ext_int -d $PRINTER -j network_printer_in

####################
# Set up the rules #
####################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Manufacturer Support "
fi

$IPTABLES -A network_printer_out -p tcp --sport $UNPRIVPORTS --dport $GOOGLE_TALK_TCP_PORT -j ACCEPT


#########################################################################################
# Specific rules for laptops
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Establishing rules for Laptops: "
fi
#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on Laptops
$IPTABLES -A int_ext -s $MYLAPTOP -j laptop_out
$IPTABLES -A ext_int -d $MYLAPTOP -j laptop_in

####################
# Set up the rules #
####################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Hangouts, "
fi

#############################
# Google Hangouts port setup
#############################
HANGOUTS_TCP_UDP_PORT_RNG="19302:19309"
$IPTABLES -A laptop_out -p udp --sport $UNPRIVPORTS --dport $HANGOUTS_TCP_UDP_PORT_RNG -j ACCEPT
$IPTABLES -A laptop_out -p tcp --sport $UNPRIVPORTS --dport $HANGOUTS_TCP_UDP_PORT_RNG -j ACCEPT

#############################
# Discord Audio Server
#############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Discord audio, "
fi

DISCORD_AUDIO_SERVER="107.160.169.222"
DISCORD_AUDIO_SERVER2="162.245.207.213"
DISCORD_UDP_PORT_RNG="50001:65535"
$IPTABLES -A laptop_out -p udp --sport $UNPRIVPORTS -d $DISCORD_AUDIO_SERVER --dport $DISCORD_UDP_PORT_RNG -j ACCEPT
$IPTABLES -A laptop_out -p udp --sport $UNPRIVPORTS -d $DISCORD_AUDIO_SERVER2 --dport $DISCORD_UDP_PORT_RNG -j ACCEPT

#############################
# IRC
#############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "IRC, "
fi

IRC_TCP_PORT_RNG1="6660:6669"
IRC_TCP_PORT_RNG2="5000:5009"
$IPTABLES -A laptop_out -p tcp --sport $UNPRIVPORTS --dport $IRC_TCP_PORT_RNG1 -j ACCEPT
$IPTABLES -A laptop_out -p tcp --sport $UNPRIVPORTS --dport $IRC_TCP_PORT_RNG2 -j ACCEPT

##############################
# Roblox
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Roblox, "
fi

ROBLOX_UDP_PORT_RNG="49152:65535"
$IPTABLES -A laptop_out -p udp --sport $UNPRIVPORTS --dport $ROBLOX_UDP_PORT_RNG -j ACCEPT
$IPTABLES -A laptop_out -p udp --sport $UNPRIVPORTS 

#############################
# Steam
#############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& Steam "
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
$IPTABLES -A laptop_out -p udp --sport $STEAM_SVR_SEARCH_UDP_PORT2 --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A laptop_out -p udp --sport $UNPRIVPORTS --dport $STEAM_FRIENDS_UDP_PORT -j ACCEPT
$IPTABLES -A laptop_out -p udp --sport $UNPRIVPORTS --dport $STEAM_UDP_PORT_RNG -j ACCEPT
$IPTABLES -A laptop_out -p udp --sport $UNPRIVPORTS --dport $STEAM_UDP_PORT_RNG2 -j ACCEPT
$IPTABLES -A laptop_out -p udp --sport $UNPRIVPORTS --dport $STEAM_UDP_PORT_RNG3 -j ACCEPT
$IPTABLES -A laptop_out -p tcp --sport $UNPRIVPORTS --dport $STEAM_TCP_PORT_RNG -j ACCEPT
$IPTABLES -A laptop_out -p tcp --sport $UNPRIVPORTS --dport $STEAM_TCP_PORT_FRIENDS_LIST -j ACCEPT
$IPTABLES -A laptop_out -p tcp --sport $UNPRIVPORTS --dport $STEAM_TCP_CROSS_CONNECT_PORT -j ACCEPT
$IPTABLES -A laptop_out -p udp --sport $UNPRIVPORTS --dport $STEAM_DED_SVR_UDP_PORT1 -j ACCEPT
$IPTABLES -A laptop_in -p udp --sport $STEAM_UDP_SRC_PORT --dport $UNPRIVPORTS -j ACCEPT


#########################################################################################
# Android phones
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Establishing rules for Android Phones: "
fi

#####################
# Set up the chains #
#####################
$IPTABLES -A int_ext -s $SAMSUNG23U -j samsungphone_out
$IPTABLES -A ext_int -d $SAMSUNG23U -j samsungphone_in
$IPTABLES -A int_ext -s $SAMSUNGS24 -j samsungphone_out
$IPTABLES -A ext_int -d $SAMSUNGS24 -j samsungphone_in

####################
# Set up the rules #
####################
#
# Deeptown: Mining server (See above for variable defs)
#
DEEPTOWN_SERVER="162.243.4.196"
DEEPTOWN_TCP_PORT="3001"
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Deeptown, "
fi
$IPTABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS -d $DEEPTOWN_SERVER --dport $DEEPTOWN_TCP_PORT -j ACCEPT
#

# World of Warcraft Companion App
#
BATTLE_NET_APP_SERVER="137.221.0.0/16"
BATTLE_NET_APP_SERVER_TCP_PORT="1119"
BATTLE_NET_APP_SERVER_TCP_PORT2="5222"
WOW_COMPANION_APP_SERVER="24.105.28.10"
WOW_COMPANION_APP_SERVER_TCP_PORT="1119"
WOW_COMPANION_APP_SERVER2="24.105.0.151"
WOW_COMPANION_APP_SERVER_TCP_PORT2="6012"
WOW_COMPANION_APP_SERVER3="24.105.29.40"
WOW_COMPANION_APP_SERVER_TCP_PORT3="8743"
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Battle.net, WoW, Diablo IV, "
fi
$IPTABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS -d $BATTLE_NET_APP_SERVER --dport $BATTLE_NET_APP_SERVER_TCP_PORT -j ACCEPT
$IPTABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS -d $BATTLE_NET_APP_SERVER --dport $BATTLE_NET_APP_SERVER_TCP_PORT2 -j ACCEPT
$IPTABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS -d $WOW_COMPANION_APP_SERVER --dport $WOW_COMPANION_APP_SERVER_TCP_PORT -j ACCEPT
$IPTABLES -A samsungphone_in -p tcp -s $WOW_COMPANION_APP_SERVER --sport $UNPRIVPORTS --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS -d $WOW_COMPANION_APP_SERVER2 --dport $WOW_COMPANION_APP_SERVER_TCP_PORT2 -j ACCEPT
$IPTABLES -A samsungphone_in -p tcp -s $WOW_COMPANION_APP_SERVER2 --sport $UNPRIVPORTS --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS -d $WOW_COMPANION_APP_SERVER3 --dport $WOW_COMPANION_APP_SERVER_TCP_PORT3 -j ACCEPT
$IPTABLES -A samsungphone_in -p tcp -s $WOW_COMPANION_APP_SERVER3 --sport $UNPRIVPORTS --dport $UNPRIVPORTS -j ACCEPT

# Roblox accessed from my cell phones
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Roblox, "
fi
ROBLOX_UDP_PORT="8092"
ROBLOX_UDP_PORT_RANGE="49152:65535"
$IPTABLES -A samsungphone_out -p udp --sport $UNPRIVPORTS --dport $ROBLOX_UDP_PORT -j ACCEPT
$IPTABLES -A samsungphone_out -p udp --sport $UNPRIVPORTS --dport $ROBLOX_UDP_PORT_RANGE -j ACCEPT

# Google services accessed from my cell phones
# DNS over TLS from my cell phones
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "DNS over TLS, "
fi
$IPTABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS --dport domain-s -j ACCEPT

# Google services accessed from my cell phones
# DNS over TLS from my cell phones
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "DNS over TLS, "
fi
$IPTABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS --dport domain-s -j ACCEPT

# Google services accessed from my cell phones
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Google Playstore, "
fi

#
# Google services 
#
$IPTABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS --dport $GOOGLE_PLAYSTORE_TCP_PORT -j ACCEPT
$IPTABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS --dport $GOOGLE_PLAYSTORE_TCP_PORT -j ACCEPT

# Google services accessed from my cell phones
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& Google Talk "
fi
$IPTABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS -d $GOOGLE_TALK_SERVER --dport $GOOGLE_TALK_TCP_PORT -j ACCEPT
$IPTABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS -d $GOOGLE_TALK_SERVER2 --dport $GOOGLE_TALK_TCP_PORT -j ACCEPT
$IPTABLES -A samsungphone_out -p tcp --sport $UNPRIVPORTS -d $GOOGLE_TALK_SERVER3 --dport $GOOGLE_TALK_TCP_PORT -j ACCEPT
$IPTABLES -A samsungphone_out -p udp --sport $UNPRIVPORTS -d $GOOGLE_TALK_SERVER --dport $GOOGLE_TALK_TCP_PORT -j ACCEPT
$IPTABLES -A samsungphone_out -p udp --sport $UNPRIVPORTS -d $GOOGLE_TALK_SERVER2 --dport $GOOGLE_TALK_TCP_PORT -j ACCEPT
$IPTABLES -A samsungphone_out -p udp --sport $UNPRIVPORTS -d $GOOGLE_TALK_SERVER3 --dport $GOOGLE_TALK_TCP_PORT -j ACCEPT
$IPTABLES -A samsungphone_out -p udp --sport $UNPRIVPORTS --dport $GOOGLE_TALK_UDP_PORT_RNG2 -j ACCEPT


#########################################################################################
# Samsung Galaxy Android Tablet
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Establishing rules for Android Tablets: "
fi
#####################
# Set up the chains #
#####################
$IPTABLES -A int_ext -s $GALAXYTAB -j galaxytablet_out
$IPTABLES -A ext_int -d $GALAXYTAB -j galaxytablet_in

####################
# Set up the rules #
####################
#
# Google Play Services
#
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Google Play, Roblox, Zooba, Among Us, Head Ball, Peppa Pig, "
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

$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $JACK_GAME_TCP_PORT1 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $TA_GOOGLE_PLAY_TCP_PORT_RNG1 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $TA_GOOGLE_PLAY_TCP_PORT1 -j ACCEPT
$IPTABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS --dport $TA_GOOGLE_PLAY_TCP_UDP_PORT1 -j ACCEPT
$IPTABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS --dport $TA_GOOGLE_PLAY_TCP_UDP_PORT_RNG -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $TA_GOOGLE_PLAY_TCP_UDP_PORT_RNG -j ACCEPT
$IPTABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS --dport $TA_GOOGLE_PLAY_TCP_UDP_PORT_RNG2 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $TA_GOOGLE_PLAY_TCP_UDP_PORT_RNG2 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $TA_GOOGLE_PLAY_PURCHASING_TCP_PORT -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $TA_GOOGLE_PLAY_TEAM_CHAT_TCP_PORT -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $TA_AGAR_TCP_PORT1 -j ACCEPT
$IPTABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS --dport $ROBLOX_UDP_PORT -j ACCEPT
$IPTABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS --dport $ROBLOX_UDP_PORT_RANGE -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $KING_OF_THIEVES_TCP_PORT1 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $DRIVE_AHEAD_TCP_PORT1 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $DRAGON_GAME_TCP_PORT1 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $DRAGON_GAME_TCP_PORT2 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $DRAGON_GAME_TCP_PORT3 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $DRAGON_GAME_TCP_PORT4 -j ACCEPT
$IPTABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS --dport $DRAGON_GAME_UDP_PORT_RNG1 -j ACCEPT
$IPTABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS --dport $AMONG_US_UDP_PORT_RNG1 -j ACCEPT
$IPTABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS --dport $AMONG_US_UDP_PORT_RNG2 -j ACCEPT
$IPTABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS --dport $AMONG_US_UDP_PORT_RNG3 -j ACCEPT
$IPTABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS --dport $AMONG_US_UDP_PORT_RNG4 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $DEVIL_AMONG_US_TCP_PORT1 -j ACCEPT
$IPTABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS --dport $HEAD_BALL_UDP_PORT1 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $PEPPA_PIG_TCP_PORT1 -j ACCEPT
FB_MESSENGER_KIDS_TCP_PORT1="3478"
FB_MESSENGER_KIDS_UDP_PORT_RNG1="40000:40009"
FB_MESSENGER_KIDS_UDP_PORT_RNG2="41400:41409"
$IPTABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS --dport $FB_MESSENGER_KIDS_UDP_PORT_RNG1 -j ACCEPT
$IPTABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS --dport $FB_MESSENGER_KIDS_UDP_PORT_RNG2 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $FB_MESSENGER_KIDS_TCP_PORT1 -j ACCEPT

if [ "$RUN_SILENTLY" != "1" ]; then
	echo " and Minecraft "
fi

MINECRAFT_TCP_PORT_1="6667"
MINECRAFT_TCP_PORT_2="12400"
MINECRAFT_TCP_PORT_3="28910"
MINECRAFT_TCP_PORT_4="29900"
MINECRAFT_TCP_PORT_5="29901"
MINECRAFT_TCP_PORT_6="29920"
MINECRAFT_UDP_PORT_RNG1="19000:19999"

$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $MINECRAFT_TCP_PORT_1 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $MINECRAFT_TCP_PORT_2 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $MINECRAFT_TCP_PORT_3 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $MINECRAFT_TCP_PORT_4 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $MINECRAFT_TCP_PORT_5 -j ACCEPT
$IPTABLES -A galaxytablet_out -p tcp --sport $UNPRIVPORTS --dport $MINECRAFT_TCP_PORT_6 -j ACCEPT
$IPTABLES -A galaxytablet_out -p udp --sport $UNPRIVPORTS --dport $MINECRAFT_UDP_PORT_RNG1 -j ACCEPT


#########################################################################################
# Netgear Orbi's specific rules for games and game servers
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Establishing rules for Orbi Base/Satellite and TP-Link AX55: "
fi

#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on the WAP
$IPTABLES -A int_ext -s $ORBI -j wap_out
$IPTABLES -A ext_int -d $ORBI -j wap_in
$IPTABLES -A int_ext -s $ORBISATELLITE -j wap_out
$IPTABLES -A ext_int -d $ORBISATELLITE -j wap_in

####################
# Set up the rules #
####################
# NTP server
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "daytime, "
fi
$IPTABLES -A wap_out -p tcp --sport $UNPRIVPORTS --dport daytime -j ACCEPT
$IPTABLES -A wap_in -p tcp --sport daytime --dport $UNPRIVPORTS -j ACCEPT

# Update server
ORBI_UPDATE_SVC_PORT="8883"

if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "update svc, "
fi
$IPTABLES -A wap_out -p tcp --sport $UNPRIVPORTS --dport $ORBI_UPDATE_SVC_PORT -j ACCEPT

# DNS server
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "domain "
fi

$IPTABLES -A wap_out -p tcp --sport $UNPRIVPORTS --dport domain -j ACCEPT
$IPTABLES -A wap_out -p tcp --sport $UNPRIVPORTS --dport domain-s -j ACCEPT


#########################################################################################
# File Server
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Establishing rules for File Server: "
fi

#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on the file server
$IPTABLES -A int_ext -s $FILESERVER -j file_server_out
$IPTABLES -A ext_int -d $FILESERVER -j file_server_in

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
	echo -n "Establishing rules for Roku: "
fi

#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on the TiVo DVR
$IPTABLES -A int_ext -s $ROKU -j roku_out
$IPTABLES -A ext_int -d $ROKU -j roku_in

####################
# Set up the rules #
####################
ROKU_UDP_PORT1="53"
ROKU_UDP_PORT2="853"
ROKU_TCP_PORT1="2350"
ROKU_GOOGLE_DNS_1="8.8.8.8"
ROKU_GOOGLE_DNS_2="8.8.4.4"

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Roku ports "
fi
$IPTABLES -A roku_out -p udp --sport $UNPRIVPORTS --dport $ROKU_UDP_PORT1 -j ACCEPT
$IPTABLES -A roku_out -p udp --sport $UNPRIVPORTS --dport $ROKU_UDP_PORT2 -j ACCEPT
$IPTABLES -A roku_out -p tcp --sport $UNPRIVPORTS --dport $ROKU_TCP_PORT1 -j ACCEPT
$IPTABLES -A roku_out -p tcp --sport $UNPRIVPORTS -d $ROKU_GOOGLE_DNS_1 --dport domain -j ACCEPT
$IPTABLES -A roku_out -p tcp --sport $UNPRIVPORTS -d $ROKU_GOOGLE_DNS_2 --dport domain -j ACCEPT
$IPTABLES -A roku_out -p tcp --sport $UNPRIVPORTS -d $ROKU_GOOGLE_DNS_1 --dport domain-s -j ACCEPT
$IPTABLES -A roku_out -p tcp --sport $UNPRIVPORTS -d $ROKU_GOOGLE_DNS_2 --dport domain-s -j ACCEPT


#########################################################################################
# Nintendo Switch
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Establishing rules for Nintendo Switch: "
fi

#####################
# Set up the chains #
#####################
$IPTABLES -A int_ext -s $NINTENDOSWITCH -j switch_out
$IPTABLES -A ext_int -d $NINTENDOSWITCH -j switch_in

####################
# Set up the rules #
####################
# Nintendo servers incoming (multiplayer, et. al)
SWITCH_UDP_PORT_FWD_RNG1="45000:65535"
SWITCH_TCP_PORT_FWD_1="25565"

if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Nintendo Switch DNAT server ports, "
fi

# DNAT for Nintendo Switch 
$IPTABLES -t nat -A PREROUTING -p udp -i $INTERNET_IF -d $INTERNET_IP --dport $SWITCH_UDP_PORT_FWD_RNG1 --sport $UNPRIVPORTS -j DNAT --to-destination $NINTENDOSWITCH

$IPTABLES -t nat -A PREROUTING -p tcp -i $INTERNET_IF -d $INTERNET_IP --dport $SWITCH_TCP_PORT_FWD_1 --sport $UNPRIVPORTS -j DNAT --to-destination $NINTENDOSWITCH

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "and Minecraft "
fi

$IPTABLES -A switch_out -p tcp --sport $UNPRIVPORTS --dport $MINECRAFT_TCP_PORT_1 -j ACCEPT
$IPTABLES -A switch_out -p tcp --sport $UNPRIVPORTS --dport $MINECRAFT_TCP_PORT_2 -j ACCEPT
$IPTABLES -A switch_out -p tcp --sport $UNPRIVPORTS --dport $MINECRAFT_TCP_PORT_3 -j ACCEPT
$IPTABLES -A switch_out -p tcp --sport $UNPRIVPORTS --dport $MINECRAFT_TCP_PORT_4 -j ACCEPT
$IPTABLES -A switch_out -p tcp --sport $UNPRIVPORTS --dport $MINECRAFT_TCP_PORT_5 -j ACCEPT
$IPTABLES -A switch_out -p tcp --sport $UNPRIVPORTS --dport $MINECRAFT_TCP_PORT_6 -j ACCEPT
$IPTABLES -A switch_out -p udp --sport $UNPRIVPORTS --dport $UNPRIVPORTS -j ACCEPT


#########################################################################################
# Specific rules for Ecobee 3 
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Establishing rules for Ecobee 3: "
fi

#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on the ecobee 3 thermostat
$IPTABLES -A int_ext -s $ECOBEE3 -j ecobee3_out
$IPTABLES -A ext_int -d $ECOBEE3 -j ecobee3_in

####################
# Set up the rules #
####################

# Ecobee 
ECOBEE3_TCP_PORT1="8089"
ECOBEE3_TCP_PORT_RNG1="8180:8199"

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Ecobee3 server ports "
fi

$IPTABLES -A ecobee3_out -p tcp --sport $UNPRIVPORTS --dport $ECOBEE3_TCP_PORT1 -j ACCEPT
$IPTABLES -A ecobee3_out -p tcp --sport $UNPRIVPORTS --dport $ECOBEE3_TCP_PORT_RNG1 -j ACCEPT


#########################################################################################
# Specific rules for Jinvoo (Hausbell) Wireless Plugs 
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Establishing rules for Wireless Plugs: "
fi

#####################
# Set up the chains #
#####################
# A TCP/UDP exchange for the Hausbell (Jinvoo) Wireless Wall Plugs
$IPTABLES -A int_ext -s $WIRELESSPLUG1 -j wirelessplug_out
$IPTABLES -A ext_int -d $WIRELESSPLUG1 -j wirelessplug_in
$IPTABLES -A int_ext -s $WIRELESSPLUG2 -j wirelessplug_out
$IPTABLES -A ext_int -d $WIRELESSPLUG2 -j wirelessplug_in

####################
# Set up the rules #
####################

# Server at AWS US-West
HAUSBELL_SERVER="54.0.0.0/8"
HAUSBELL_SERVER2="52.0.0.0/8"
HAUSBELL_TCP_PORT1="1883"

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Hausbell server ports "
fi

$IPTABLES -A wirelessplug_out -p tcp --sport $UNPRIVPORTS -d $HAUSBELL_SERVER --dport $HAUSBELL_TCP_PORT1 -j ACCEPT
$IPTABLES -A wirelessplug_out -p tcp --sport $UNPRIVPORTS -d $HAUSBELL_SERVER2 --dport $HAUSBELL_TCP_PORT1 -j ACCEPT


#########################################################################################
# Specific rules for the Steam Deck 
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Establishing rules for Steam Deck: "
fi

#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on a SteamDeck
$IPTABLES -A int_ext -s $STEAMDECK_WL -j steamdeck_out
$IPTABLES -A ext_int -d $STEAMDECK_WL -j steamdeck_in
$IPTABLES -A int_ext -s $STEAMDECK_DOCK -j steamdeck_out
$IPTABLES -A ext_int -d $STEAMDECK_DOCK -j steamdeck_in

####################
# Set up the rules #
####################

# Steam
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Steam, "
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
$IPTABLES -A steamdeck_out -p udp --sport $STEAM_SVR_SEARCH_UDP_PORT2 --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A steamdeck_out -p udp --sport $UNPRIVPORTS --dport $STEAM_FRIENDS_UDP_PORT -j ACCEPT
$IPTABLES -A steamdeck_out -p udp --sport $UNPRIVPORTS --dport $STEAM_UDP_PORT_RNG -j ACCEPT
$IPTABLES -A steamdeck_out -p udp --sport $UNPRIVPORTS --dport $STEAM_UDP_PORT_RNG2 -j ACCEPT
$IPTABLES -A steamdeck_out -p udp --sport $UNPRIVPORTS --dport $STEAM_UDP_PORT_RNG3 -j ACCEPT
$IPTABLES -A steamdeck_out -p tcp --sport $UNPRIVPORTS --dport $STEAM_TCP_PORT_RNG -j ACCEPT
$IPTABLES -A steamdeck_out -p tcp --sport $UNPRIVPORTS --dport $STEAM_TCP_PORT_FRIENDS_LIST -j ACCEPT
$IPTABLES -A steamdeck_in -p udp --sport $UNPRIVPORTS --dport $STEAM_DED_SVR_UDP_RNG -j ACCEPT
$IPTABLES -A steamdeck_in -p udp --sport $STEAM_UDP_SRC_PORT --dport $UNPRIVPORTS -j ACCEPT


#########################################################################################
# Gaming PC specific rules for games and game servers
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Establishing rules for Gaming PC: "
fi
#####################
# Set up the chains #
#####################
# A TCP/UDP exchange on the Gaming PC
$IPTABLES -A int_ext -s $GAMINGPC -j gaming_pc_out
$IPTABLES -A ext_int -d $GAMINGPC -j gaming_pc_in

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
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $EL_TCP_PORT1 -j ACCEPT

##############################
# GoG Galaxy Launcher
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "GoG Galaxy, "
fi
# Constants
GOG_UDP_PORT1="514"
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS --dport $GOG_UDP_PORT1 -j ACCEPT

##############################
# VNC
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "VNC (client), "
fi
# Constants 
VNC_TCP_PORT_RANGE="5900:5909"
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $VNC_TCP_PORT_RANGE -j ACCEPT

##############################
# Mass Effect (1)
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n " Mass Effect, "
fi
# Constants 
ME_TCP_PORT1="5290"
ME_TCP_PORT2="42100"
ME_TCP_PORT_RANGE_1="15200:15300"
ME_TCP_PORT_RANGE_2="9945:9994"
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $ME_TCP_PORT1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $ME_TCP_PORT2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $ME_TCP_PORT_RANGE_1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $ME_TCP_PORT_RANGE_2 -j ACCEPT

##############################
# Mass Effect 2
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Mass Effect 2, "
fi
# Constants 
ME2_TCP_PORT1="2967"
ME2_TCP_PORT2="42100"
ME2_TCP_PORT_RANGE_1="15200:15300"
ME2_TCP_PORT_RANGE_2="9945:9994"
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $ME2_TCP_PORT1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $ME2_TCP_PORT2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $ME2_TCP_PORT_RANGE_1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $ME2_TCP_PORT_RANGE_2 -j ACCEPT

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
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $ME3_TCP_PORT1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $ME3_TCP_PORT2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $ME3_TCP_PORT_RANGE_1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $ME3_TCP_PORT_RANGE_2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS --dport $ME3_UDP_PORT_RANGE_1 -j ACCEPT

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
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $MEA_TCP_PORT1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $MEA_TCP_PORT2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $MEA_TCP_PORT3 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $MEA_TCP_PORT4 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $MEA_TCP_PORT_RANGE_1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS --dport $MEA_UDP_PORT_RANGE_1 -j ACCEPT


##############################
# TikTok (live)
##############################

if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "TikTok (live), "
fi
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $GGOGLE_TALK_SERVER_RANGE --dport $GOOGLE_TALK_UDP_PORT_RNG -j ACCEPT


##############################
# Google Voice
##############################

if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Google Voice, "
fi
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $GGOGLE_TALK_SERVER_RANGE --dport $GOOGLE_TALK_UDP_PORT_RNG -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $GGOGLE_TALK_SERVER_RANGE --dport $GOOGLE_TALK_UDP_PORT_RNG2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $GGOGLE_TALK_SERVER_RANGE2 --dport $GOOGLE_TALK_UDP_PORT_RNG -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $GGOGLE_TALK_SERVER_RANGE2 --dport $GOOGLE_TALK_UDP_PORT_RNG2 -j ACCEPT


##############################
# Golf with Your Friends
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Golf w/Your Friends, "
fi
# Constants 

# Server Range
GWYF_SERVER="40.76.47.124"
GWYF_SERVER2="92.223.82.17"

# UDP
GWYF_UDP_PORT_RANGE_1="5050:5059"

$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $GWYF_SERVER --dport $GWYF_UDP_PORT_RANGE_1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $GWYF_SERVER2 --dport $GWYF_UDP_PORT_RANGE_1 -j ACCEPT


##############################
# Destiny 2
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n " Destiny 2, "
fi
# Constants 

# Server Range
D2_SERVERS="172.97.50.0/20"
D2_SERVERS_2="205.209.21.0/24"

# TCP
D2_TCP_PORT1="3074"
D2_TCP_PORT2="3724"
D2_TCP_PORT3="4000"
D2_TCP_PORT_RANGE_1="1119:1120"
D2_TCP_PORT_RANGE_2="6112:6114"
D2_TCP_PORT_RANGE_3="7500:7509"
D2_TCP_PORT_RANGE_4="30000:30009"

# UDP
D2_UDP_PORT1="3074"
D2_UDP_PORT2="3724"
D2_UDP_PORT3="4000"
D2_UDP_PORT4="55191"
D2_UDP_SOURCE_PORT1="3097"
D2_UDP_PORT_RANGE_1="1119:1120"
D2_UDP_PORT_RANGE_2="3097:3196"
D2_UDP_PORT_RANGE_3="6112:6114"

# Rules
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -d $D2_SERVERS --dport $D2_TCP_PORT1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -d $D2_SERVERS --dport $D2_TCP_PORT2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -d $D2_SERVERS --dport $D2_TCP_PORT3 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -d $D2_SERVERS --dport $D2_TCP_PORT_RANGE_1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -d $D2_SERVERS --dport $D2_TCP_PORT_RANGE_2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -d $D2_SERVERS --dport $D2_TCP_PORT_RANGE_3 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $D2_TCP_PORT_RANGE_4 -j ACCEPT

$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $D2_SERVERS --dport $D2_UDP_PORT1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $D2_SERVERS --dport $D2_UDP_PORT2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $D2_SERVERS --dport $D2_UDP_PORT3 -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $D2_SERVERS --dport $D2_UDP_PORT4 -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $D2_UDP_SOURCE_PORT1 --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $D2_SERVERS --dport $D2_UDP_PORT_RANGE_1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $D2_SERVERS --dport $D2_UDP_PORT_RANGE_2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $D2_SERVERS --dport $D2_UDP_PORT_RANGE_3 -j ACCEPT


##############################
# World of Warcraft
##############################
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
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $WOW_TCP_PORT_RNG1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $WOW_TCP_PORT1 --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $WOW_TCP_PORT1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $WOW_TCP_PORT2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $WOW_TCP_PORT3 --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $WOW_TCP_PORT4 -j ACCEPT
$IPTABLES -A gaming_pc_in -p tcp --sport $UNPRIVPORTS --dport $WOW_TCP_PORT1 -j ACCEPT
$IPTABLES -A gaming_pc_in -p udp --sport $UNPRIVPORTS --dport $WOW_TCP_PORT1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $WOW_TCP_CRASH_REPORT_PORT1 -j ACCEPT
# DNAT for World of Warcraft patch downloader
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "WoW Downloader, "
fi
$IPTABLES -t nat -A PREROUTING -p tcp -i $INTERNET_IF -d $INTERNET_IP --dport $WOW_TCP_PORT1 --sport $UNPRIVPORTS -j DNAT --to-destination $GAMINGPC
$IPTABLES -t nat -A PREROUTING -p tcp -i $INTERNET_IF -d $INTERNET_IP --dport $WOW_TCP_PORT_RNG2 --sport $WOW_TCP_PORT1 -j DNAT --to-destination $GAMINGPC
$IPTABLES -t nat -A PREROUTING -p udp -i $INTERNET_IF -d $INTERNET_IP --dport $WOW_TCP_PORT1 --sport $UNPRIVPORTS -j DNAT --to-destination $GAMINGPC
$IPTABLES -t nat -A PREROUTING -p udp -i $INTERNET_IF -d $INTERNET_IP --dport $WOW_TCP_PORT_RNG2 --sport $WOW_TCP_PORT1 -j DNAT --to-destination $GAMINGPC

##############################
# Diablo IV
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Diablo IV, "
fi

# Constants 
D4_SRC_TCP_PORT_RNG1="62000:62999"
D4_SERVER_TCP_PORT_RNG1="54540:54549"
D4_QUEUE_TCP_PORT_RNG1="28890:28899"

$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $D4_SERVER_TCP_PORT_RNG1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $D4_QUEUE_TCP_PORT_RNG1 -j ACCEPT


##############################
# Final Fantasy XIV
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "FFXIV, "
fi
# Constants 
FFXIV_TCP_PORT_RNG1="54992:54994"
FFXIV_TCP_PORT_RNG2="55006:55007"
FFXIV_TCP_PORT_RNG3="55021:55040"
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $FFXIV_TCP_PORT_RNG1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $FFXIV_TCP_PORT_RNG2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $FFXIV_TCP_PORT_RNG3 -j ACCEPT

##############################
# Lost Ark
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Lost Ark, "
fi
# Constants 
LARK_TCP_PORT_RNG1="44330:44339"
LARK_TCP_PORT_RNG2="6000:6050"
LARK_TCP_PORT_RNG3="55021:55040"
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $LARK_TCP_PORT_RNG1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $LARK_TCP_PORT_RNG2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $LARK_TCP_PORT_RNG3 -j ACCEPT

##############################
# Guild Wars 2, Rift, Magic: Legends
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Guild Wars 2, Magic: Legends, "
fi
# Constants 
GW2_TCP_PORT1="6112"
GW2_TCP_PORT2="6600"
ML_TCP_PORT_RNG1="7000:7500"
RIFT_TCP_PORT_RNG1="6520:6540"
$IPTABLES -A gaming_pc_out -p tcp --sport $GW2_TCP_PORT1 --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $GW2_TCP_PORT2 --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $GW2_TCP_PORT2 -j ACCEPT
$IPTABLES -A gaming_pc_in -p tcp --sport $UNPRIVPORTS --dport $GW2_TCP_PORT1 -j ACCEPT
$IPTABLES -A gaming_pc_in -p tcp --sport $UNPRIVPORTS --dport $GW2_TCP_PORT2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $RIFT_TCP_PORT_RNG1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $ML_TCP_PORT_RNG1 -j ACCEPT
# DNAT for Guild Wars 2
$IPTABLES -t nat -A PREROUTING -p tcp -i $INTERNET_IF -d $INTERNET_IP --dport $GW2_TCP_PORT1 --sport $UNPRIVPORTS -j DNAT --to-destination $GAMINGPC
$IPTABLES -t nat -A PREROUTING -p tcp -i $INTERNET_IF -d $INTERNET_IP --dport $GW2_TCP_PORT2 --sport $UNPRIVPORTS -j DNAT --to-destination $GAMINGPC

##############################
# First Descendant
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n " The First Descendant, "
fi
# Constants 
TFD_TCP_PORT1="27777"
TFD_TCP_PORT2="28909"
TFD_UDP_PORT_RNG1="17700:17999"
TFD_UDP_PORT1="52848"
$IPTABLES -A gaming_pc_out -p tcp --dport $TFD_TCP_PORT1 --sport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --dport $TFD_TCP_PORT2 --sport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --dport $TFD_UDP_PORT_RNG1 --sport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --dport $TFD_UDP_PORT1 --sport $UNPRIVPORTS -j ACCEPT

##############################
# Torchlight 2
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Torchlight 2, "
fi
# Constants 
TL2_TCP_PORT1="4549"
TL2_UDP_PORT2="59243"
$IPTABLES -A gaming_pc_out -p tcp --dport $TL2_TCP_PORT1 --sport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --dport $TL2_UDP_PORT2 --sport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A gaming_pc_in -p tcp --sport $UNPRIVPORTS --dport $TL2_TCP_PORT1 -j ACCEPT
$IPTABLES -A gaming_pc_in -p udp --sport $UNPRIVPORTS --dport $TL2_UDP_PORT2 -j ACCEPT

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
$IPTABLES -A gaming_pc_out -p udp --sport $STEAM_SVR_SEARCH_UDP_PORT2 --dport $UNPRIVPORTS -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS --dport $STEAM_FRIENDS_UDP_PORT -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS --dport $STEAM_UDP_PORT_RNG -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS --dport $STEAM_UDP_PORT_RNG2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS --dport $STEAM_UDP_PORT_RNG3 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $STEAM_TCP_PORT_RNG -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $STEAM_TCP_PORT_FRIENDS_LIST -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $STEAM_TCP_CROSS_CONNECT_PORT -j ACCEPT
$IPTABLES -A gaming_pc_in -p udp --sport $UNPRIVPORTS --dport $STEAM_DED_SVR_UDP_RNG -j ACCEPT
$IPTABLES -A gaming_pc_in -p udp --sport $STEAM_UDP_SRC_PORT --dport $UNPRIVPORTS -j ACCEPT
# DNAT for Steam
$IPTABLES -t nat -A PREROUTING -p udp -i $INTERNET_IF -d $INTERNET_IP --dport $STEAM_DED_SVR_UDP_PORT1 --sport $UNPRIVPORTS -j DNAT --to-destination $GAMINGPC
$IPTABLES -t nat -A PREROUTING -p udp -i $INTERNET_IF -d $INTERNET_IP --dport $STEAM_DED_SVR_UDP_PORT2 --sport $UNPRIVPORTS -j DNAT --to-destination $GAMINGPC

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
$IPTABLES -A gaming_pc_out -p udp --sport $GFW_LIVE_UDP_PORT --dport $GFWL_UDP_PORT -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS --dport $GFW_LIVE_UDP_PORT -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS --dport $GFWL_UDP_PORT3 -j ACCEPT
# DNAT for GFWL
$IPTABLES -t nat -A PREROUTING -p udp -i $INTERNET_IF -d $INTERNET_IP --dport $GFWL_UDP_PORT --sport $UNPRIVPORTS -j DNAT --to-destination $GAMINGPC
$IPTABLES -t nat -A PREROUTING -p udp -i $INTERNET_IF -d $INTERNET_IP --dport $GFW_LIVE_UDP_PORT --sport $UNPRIVPORTS -j DNAT --to-destination $GAMINGPC
$IPTABLES -t nat -A PREROUTING -p udp -i $INTERNET_IF -d $INTERNET_IP --sport $GFWL_UDP_PORT2 --dport $UNPRIVPORTS -j DNAT --to-destination $GAMINGPC
$IPTABLES -t nat -A PREROUTING -p tcp -i $INTERNET_IF -d $INTERNET_IP --dport $GFWL_TCP_PORT --sport $UNPRIVPORTS -j DNAT --to-destination $GAMINGPC

##############################
# Path of Exile
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Path of Exile, "
fi
# Constants 
POE_AMERICA_IP="173.193.0.0/16"
POE_TCP_PORT1="8095"
POE_TCP_PORT2="12995"
POE_TCP_PORT3="20481"
POE_TCP_PORT4="46637"
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $POE_TCP_PORT1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $POE_TCP_PORT2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $POE_TCP_PORT3 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $POE_TCP_PORT4 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -d $POE_AMERICA_IP --dport $UNPRIVPORTS -j ACCEPT

##############################
# Google services
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Google, "
fi
# Constants 
GOOGLE_IP1="216.17.0.0/16"
GOOGLE_IP2="172.253.0.0/16"
GOOGLE_TCP_PORT_RANGE1="4200:4299"
GOOGLE_TCP_PORT_RANGE2="5912:5912"
GOOGLE_TCP_SDNS_PORT="5228"
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -d $GOOGLE_IP1 --dport $GOOGLE_TCP_PORT_RANGE1 -j ACCEPT
$IPTABLES -A gaming_pc_in -p tcp -s $GOOGLE_IP1 --sport $UNPRIVPORTS --dport $GOOGLE_TCP_PORT_RANGE1 -j ACCEPT
$IPTABLES -A gaming_pc_in -p tcp -s $GOOGLE_IP1 --sport $UNPRIVPORTS --dport $GOOGLE_TCP_PORT_RANGE2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -d $GOOGLE_IP2 --dport $GOOGLE_TCP_SDNS_PORT -j ACCEPT
# DNAT for Google
$IPTABLES -t nat -A PREROUTING -p tcp -i $INTERNET_IF -d $INTERNET_IP -s $GOOGLE_IP1 --sport $UNPRIVPORTS --dport $GOOGLE_TCP_PORT_RANGE1 -j DNAT --to-destination $GAMINGPC
$IPTABLES -t nat -A PREROUTING -p tcp -i $INTERNET_IF -d $INTERNET_IP -s $GOOGLE_IP1 --sport $UNPRIVPORTS --dport $GOOGLE_TCP_PORT_RANGE2 -j DNAT --to-destination $GAMINGPC

##############################
# SWTOR
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "SWTOR, "
fi
# Constants 
SWTOR_AMERICA_IP="159.153.65.0/24"
SWTOR_AMERICA_IP2="159.153.66.0/24"
SWTOR_TCP_PORT_RNG1="8995:8995"
SWTOR_TCP_PORT_RNG2="20000:29999"
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -d $SWTOR_AMERICA_IP --dport $SWTOR_TCP_PORT_RNG1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -d $SWTOR_AMERICA_IP --dport $SWTOR_TCP_PORT_RNG2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -d $SWTOR_AMERICA_IP2 --dport $SWTOR_TCP_PORT_RNG1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -d $SWTOR_AMERICA_IP2 --dport $SWTOR_TCP_PORT_RNG2 -j ACCEPT

##############################
# Elder Scrolls Online
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ESO, "
fi
# Constants 
ESO_IP1="198.20.200.0/24"
ESO_PORT_RANGE1="24100:24131"
ESO_PORT_RANGE2="24300:24331"
ESO_PORT_RANGE3="24500:24507"
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -d $ESO_IP1 --dport $ESO_PORT_RANGE1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -d $ESO_IP1 --dport $ESO_PORT_RANGE2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -d $ESO_IP1 --dport $ESO_PORT_RANGE3 -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $ESO_IP1 --dport $ESO_PORT_RANGE1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $ESO_IP1 --dport $ESO_PORT_RANGE2 -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $ESO_IP1 --dport $ESO_PORT_RANGE3 -j ACCEPT

##############################
# GOG (Good, Old Games)
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n " GOG, "
fi

GOG_SERVER1="77.79.249.151"
GOG_SERVER2="77.79.249.152"
GOG_UDP_PORT_LIST="514"
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $GOG_SERVER1 -m multiport --dports $GOG_UDP_PORT_LIST -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $GOG_SERVER2 -m multiport --dports $GOG_UDP_PORT_LIST -j ACCEPT

##############################
# New World
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "New World, "
fi

NEW_WORLD_UDP_PORT1="33435"
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS --dport $NEW_WORLD_UDP_PORT1 -j ACCEPT

##############################
# Discord Audio Server
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Discord audio, "
fi

DISCORD_AUDIO_SERVER="107.160.169.222"
DISCORD_AUDIO_SERVER2="162.245.207.213"
DISCORD_UDP_PORT_RNG="50001:65535"
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $DISCORD_AUDIO_SERVER --dport $DISCORD_UDP_PORT_RNG -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS -d $DISCORD_AUDIO_SERVER2 --dport $DISCORD_UDP_PORT_RNG -j ACCEPT

##############################
# Roblox
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Roblox, "
fi

ROBLOX_UDP_PORT_RNG="49152:65535"
ROBLOX_TCP_PORT1="51007"
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS --dport $ROBLOX_UDP_PORT_RNG -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $ROBLOX_TCP_PORT1 -j ACCEPT

##############################
# No Man's Sky
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "No Man's Sky, "
fi
NMS_TCP_STEAM_PORT_LIST="27015,27036"
NMS_UDP_STEAM_PORT="27015"
NMS_UDP_STEAM_PORT_RNG1="27031:27036"
NMS_UDP_SERVER_PORT_RNG1="30000:31999"
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS --dport $NMS_UDP_STEAM_PORT -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --sport $UNPRIVPORTS -m multiport --dports $NMS_TCP_STEAM_PORT_LIST -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS --dport $NMS_UDP_STEAM_PORT_RNG1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS --dport $NMS_UDP_SERVER_PORT_RNG1 -j ACCEPT

##############################
# Disney Dreamlight Valley
##############################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "Disney Dreamlight Valley, "
fi
DDV_UDP_STEAM_PORT_RNG1="27050:27059"
$IPTABLES -A gaming_pc_out -p udp --sport $UNPRIVPORTS --dport $DDV_UDP_STEAM_PORT_RNG1 -j ACCEPT

##############################
# Microsoft games
##############################
# Age of Empires II server ports
AOE_II_TCP_PORT="47624"
AOE_II_TCP_PORT_RANGE_1="2300:2400"
AOE_II_UDP_PORT_RANGE_2="2300:2400"
ALPHA_CENTARI_UDP_PORT_RANGE="1900:2000"
ALPHA_CENTARI_TCP_PORT="6073"

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& Microsoft Games"
fi
$IPTABLES -A gaming_pc_out -p tcp --dport $AOE_II_TCP_PORT -j ACCEPT
$IPTABLES -A gaming_pc_out -p tcp --dport $AOE_II_TCP_PORT_RANGE_1 -j ACCEPT
$IPTABLES -A gaming_pc_out -p udp --dport $AOE_II_UDP_PORT_RANGE_2 -j ACCEPT
$IPTABLES -A gaming_pc_in -p tcp --dport $AOE_II_TCP_PORT -j ACCEPT
$IPTABLES -A gaming_pc_in -p tcp --dport $AOE_II_TCP_PORT_RANGE_1 -j ACCEPT
$IPTABLES -A gaming_pc_in -p udp --dport $AOE_II_UDP_PORT_RANGE_2 -j ACCEPT


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
	echo "Blocking and logging illegal TCP states."
fi
# All bits are cleared
$IPTABLES -A tcp_state_flags -p tcp --tcp-flags ALL NONE -j log_tcp_state
# SYN and FIN are both set
$IPTABLES -A tcp_state_flags -p tcp --tcp-flags SYN,FIN SYN,FIN -j log_tcp_state
# SYN and RST are both set
$IPTABLES -A tcp_state_flags -p tcp --tcp-flags SYN,RST SYN,RST -j log_tcp_state
# FIN and RST are both set
$IPTABLES -A tcp_state_flags -p tcp --tcp-flags FIN,RST FIN,RST -j log_tcp_state
# FIN is the only bit set without the expected accompanying ACK
$IPTABLES -A tcp_state_flags -p tcp --tcp-flags ACK,FIN FIN -j log_tcp_state
# PSH is the only bit set without the expected accompanying ACK
$IPTABLES -A tcp_state_flags -p tcp --tcp-flags ACK,PSH PSH -j log_tcp_state
# URG is the only bit set without the expected accompanying ACK
$IPTABLES -A tcp_state_flags -p tcp --tcp-flags ACK,URG URG -j log_tcp_state

#########################################################################################
# Log and drop TCP packets with bad state combinations
#########################################################################################
$IPTABLES -A log_tcp_state -p tcp -j LOG --log-prefix "(D)Illegal TCP state: " --log-ip-options --log-tcp-options
$IPTABLES -A log_tcp_state -j DROP


#########################################################################################
# By-pass rule checking for ESTABLISHED exchanges
#########################################################################################
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
 	if [ "$RUN_SILENTLY" != "1" ]; then
  		echo "Setting ESTABLISHED,RELATED Connection Tracking rule."
 	fi
	$IPTABLES -A connection_tracking -m state --state ESTABLISHED,RELATED -j ACCEPT
 	# But drop INVALID connections
 	if [ "$RUN_SILENTLY" != "1" ]; then
  	echo "Setting INVALID state Connection Tracking to drop."
 	fi
	$IPTABLES -A connection_tracking -m state --state INVALID -j DROP
fi


#########################################################################################
# Firewall DHCP client to remote DHCP server traffic
#########################################################################################
# Some broadcast packets are explicitly ignored by the firewall.
# Others are dropped by the default policy.
# DHCP tests must precede broadcast-related rules, as DHCP relies
# on broadcast traffic initially.
if [ "$ISA_DHCP_CLIENT" = "1" ]; then
 	if [ "$RUN_SILENTLY" != "1" ]; then
  		echo "Setting local F/W DHCP client to remote DHCP server rules."
 	fi
 	# Initialization or rebinding: No lease or Lease time expired.
	$IPTABLES -A lcl_dhcp_client_query -s $BROADCAST_SRC -d $BROADCAST_DEST -j ACCEPT
 	# Incoming DHCPOFFER from available DHCP servers
	$IPTABLES -A rmt_dhcp_srv_response -s $BROADCAST_SRC -d $BROADCAST_DEST -j ACCEPT
 	# Fall back to initialization
 	# The client knows its server, but has either lost its lease,
 	# or else needs to reconfirm the IP address after rebooting.
	$IPTABLES -A lcl_dhcp_client_query -s $BROADCAST_SRC -d $REMOTE_DHCP_SERVER -j ACCEPT
	$IPTABLES -A rmt_dhcp_srv_response -s $REMOTE_DHCP_SERVER -d $BROADCAST_DEST -j ACCEPT
 	# As a result of the above, we're supposed to change our IP
 	# address with this message, which is addressed to our new
 	# address before the dhcp client has received the update.
 	# Depending on the server implementation, the destination address
 	# can be the new IP address, the subnet address, or the limited
 	# broadcast address.
 	# If the network subnet address is used as the destination,
 	# the next rule must allow incoming packets destined to the
 	# subnet address, and the rule must precede any general rules 
 	# that block such incoming broadcast packets.

 	# Request to our nearest gateway
	$IPTABLES -A rmt_dhcp_srv_response -s $REMOTE_DHCP_SERVER -j ACCEPT
 	# Lease renewal 
	$IPTABLES -A lcl_dhcp_client_query -s $INTERNET_IP -d $REMOTE_DHCP_SERVER -j ACCEPT

 	# Response/Request from/to ISP's delegated network
	$IPTABLES -A rmt_dhcp_srv_response -s $ISP_DELEGATED_DHCP_SERVER -j ACCEPT
 	# Lease renewal 
	$IPTABLES -A lcl_dhcp_client_query -s $INTERNET_IP -d $ISP_DELEGATED_DHCP_SERVER -j ACCEPT
fi

#########################################################################################
# Firewall DHCP server to LAN DHCP client traffic
#########################################################################################
# Some broadcast packets are explicitly ignored by the firewall.
# Others are dropped by the default policy.
# DHCP tests must precede broadcast-related rules, as DHCP relies
# on broadcast traffic initially.
if [ "$ISA_DHCP_SERVER" = "1" ]; then
 	if [ "$RUN_SILENTLY" != "1" ]; then
  		echo "Setting local F/W DHCP server to LAN DHCP client rules."
 	fi
 	#Initialization or rebinding: No lease or Lease time expired.
	$IPTABLES -A LAN_dhcp_client_query -s $BROADCAST_SRC -d $BROADCAST_DEST -j ACCEPT
 	# Outgoing DHCPOFFER from DHCP server
	$IPTABLES -A LAN_dhcp_srv_response -s $BROADCAST_SRC -d $BROADCAST_DEST -j ACCEPT

 	# Fall back to initialization
 	# The client knows its server, but has either lost its lease,
 	# or else needs to reconfirm the IP address after rebooting.
	$IPTABLES -A LAN_dhcp_client_query -s $LAN_SUBNET -d $BROADCAST_DEST -j ACCEPT
	$IPTABLES -A LAN_dhcp_srv_response -s $LOCAL_DHCP_SERVER -d $LAN_SUBNET -j ACCEPT

 	# The following ruleset exists for an ancient MoCA adapter that
 	# always sets its IP address to an IPv4 link local address. It 
 	# seems to do this before any time it can't immediately get a 
 	# valid IPv4 address from our DHCP server.
 
 	# As a result of the above, the client is supposed to change their 
 	# IP address with this message, which is addressed to the new
 	# address before the dhcp client has received the update.
 	# Depending on the server implementation, the destination address
 	# can be the new IP address, the subnet address, or the limited
 	# broadcast address.
 
 	# If the network subnet address is used as the destination,
 	# the next rule must allow incoming packets destined to the
 	# subnet address, and the rule must precede any general rules 
 	# that block such incoming broadcast packets.
	$IPTABLES -A LAN_dhcp_srv_response -s $LOCAL_DHCP_SERVER -j ACCEPT
 	# Lease renewal 
	$IPTABLES -A LAN_dhcp_client_query -s $LAN_SUBNET -d $LOCAL_DHCP_SERVER -j ACCEPT

 	# NIM rules for DHCP
 	CLINK_SUBNET_RANGE="169.254.1.0/24" # Initial subnet of the Motorola NIM 100 when looking up DHCP service
 	if [ "$RUN_SILENTLY" != "1" ]; then
  		echo "Setting local DHCP server to LAN DHCP client rules for c.Link (NIM100)."
 	fi
 	#Initialization or rebinding: No lease or Lease time expired.
	$IPTABLES -A LAN_dhcp_client_query -s $CLINK_SUBNET_RANGE -d $BROADCAST_DEST -j ACCEPT
 	# Outgoing DHCPOFFER from DHCP server
	$IPTABLES -A LAN_dhcp_srv_response -s $CLINK_SUBNET_RANGE -d $BROADCAST_DEST -j ACCEPT

 	# Fall back to initialization
 	# The client knows its server, but has either lost its lease,
 	# or else needs to reconfirm the IP address after rebooting.
	$IPTABLES -A LAN_dhcp_client_query -s $CLINK_SUBNET_RANGE -d $BROADCAST_DEST -j ACCEPT
	$IPTABLES -A LAN_dhcp_srv_response -s $LOCAL_DHCP_SERVER -d $CLINK_SUBNET_RANGE -j ACCEPT

 	# As a result of the above, the client is supposed to change their 
 	# IP address with this message, which is addressed to the new
 	# address before the dhcp client has received the update.
 	# Depending on the server implementation, the destination address
 	# can be the new IP address, the subnet address, or the limited
 	# broadcast address.
 	# If the network subnet address is used as the destination,
 	# the next rule must allow incoming packets destined to the
 	# subnet address, and the rule must precede any general rules 
 	# that block such incoming broadcast packets.
	$IPTABLES -A LAN_dhcp_srv_response -s $LOCAL_DHCP_SERVER -j ACCEPT
 	# Lease renewal 
	$IPTABLES -A LAN_dhcp_client_query -s $CLINK_SUBNET_RANGE -d $LOCAL_DHCP_SERVER -j ACCEPT
fi

#########################################################################################
# Source Address Spoof Checks
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Source address check."
fi
# Drop packets pretending to be originating from the INTERNET_IF IP address
$IPTABLES -A source_address_check -s $INTERNET_IP -j LOG --log-prefix "(D)SrcAddrCk(ownIP): "
$IPTABLES -A source_address_check -s $INTERNET_IP -j DROP
# Refuse packets claiming to be from private networks or reserved addresses
$IPTABLES -A source_address_check -s $CLASS_A -j LOG --log-prefix "(D)SrcAddrCk(ClassA): " 
$IPTABLES -A source_address_check -s $CLASS_A -j DROP 
$IPTABLES -A source_address_check -s $CLASS_B -j LOG --log-prefix "(D)SrcAddrCk(ClassB): " 
$IPTABLES -A source_address_check -s $CLASS_B -j DROP 
###########
## If this is NOT operating as an internal firewall, apply the following rules
###########
if [ "$INTERNAL_FIREWALL" == "0" ]; then
	echo "Source address check (not an Internal firewall)."
	$IPTABLES -A source_address_check -s $CLASS_C -j LOG --log-prefix "(D)SrcAddrCk(ClassC): " 
	$IPTABLES -A source_address_check -s $CLASS_C -j DROP 
	$IPTABLES -A source_address_check -s $CLASS_D_MULTICAST -j LOG --log-prefix "(D)SrcAddrCk(ClassD): " 
	$IPTABLES -A source_address_check -s $CLASS_D_MULTICAST -j DROP 
	$IPTABLES -A source_address_check -d $BROADCAST_DEST -j LOG --log-prefix "(D)SrcAddrCk(BrdCst): " 
	$IPTABLES -A source_address_check -d $BROADCAST_DEST -j DROP
fi
$IPTABLES -A source_address_check -s $LOOPBACK -j LOG --log-prefix "(D)SrcAddrCk(LoopB): " 
$IPTABLES -A source_address_check -s $LOOPBACK -j DROP
$IPTABLES -A source_address_check -s 0.0.0.0/8 -j LOG --log-prefix "(D)SrcAddrCk(Any): " 
$IPTABLES -A source_address_check -s 0.0.0.0/8 -j DROP 
$IPTABLES -A source_address_check -s 169.254.0.0/16 -j LOG --log-prefix "(D)SrcAddrCk(TestNtwk): " 
$IPTABLES -A source_address_check -s 169.254.0.0/16 -j DROP 

#########################################################################################
# Bad Destination Address and Port Checks
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Destination address check."
fi
# Block directed broadcasts from the Internet
###########
## If this is NOT operating as an internal firewall, apply the following rules
###########
if [ "$INTERNAL_FIREWALL" == "0" ]; then
	$IPTABLES -A destination_address_check -d $INTERNET_BASE -j LOG --log-prefix "(D)DstAddrCk(BdCstSubNet): " 
	$IPTABLES -A destination_address_check -d $INTERNET_BASE -j DROP 
	$IPTABLES -A destination_address_check ! -s $LAN_SUBNET -d $INTERNET_BROADCAST -j LOG --log-prefix "(D)DstAddrCk(BdCst): " 
	$IPTABLES -A destination_address_check ! -s $LAN_SUBNET -d $INTERNET_BROADCAST -j DROP 
fi
# Accept IGMP traffic
$IPTABLES -A destination_address_check -p igmp -d $IGMP_MULTICAST -j ACCEPT 
$IPTABLES -A destination_address_check -p igmp -d $IGMP_MULTICAST_V3 -j ACCEPT 
$IPTABLES -A destination_address_check -p igmp -s $LAN_SUBNET -d $DNS_MULTICAST -j ACCEPT 
$IPTABLES -A destination_address_check -p udp -s $LAN_SUBNET -d $DNS_MULTICAST -j ACCEPT 
$IPTABLES -A destination_address_check ! -p udp -d $CLASS_D_MULTICAST -j LOG --log-prefix "(D)DstAddrCk(MultiCst): " 
$IPTABLES -A destination_address_check ! -p udp -d $CLASS_D_MULTICAST -j DROP 

# TCP unprivileged ports
# Deny connection requests to NFS, SOCKS and X Window ports (except internal X Window requests)
$IPTABLES -A destination_address_check -p tcp -m multiport --destination-port $NFS_PORT,$SOCKS_PORT,$SQUID_PORT --syn -j LOG --log-prefix "(D)DstAddrCk(CmnPrtsTCP): " 
$IPTABLES -A destination_address_check -p tcp -m multiport --destination-port $NFS_PORT,$SOCKS_PORT,$SQUID_PORT --syn -j DROP 
$IPTABLES -A destination_address_check ! -s $LAN_SUBNET -p tcp --syn --destination-port $XWINDOW_PORTS -j LOG --log-prefix "(D)DstAddrCk(Xwindow-Ext): " 
$IPTABLES -A destination_address_check ! -s $LAN_SUBNET -p tcp --syn --destination-port $XWINDOW_PORTS -j DROP 
# UDP unprivileged ports
# Deny connection requests to NFS and lockd ports
$IPTABLES -A destination_address_check -p udp -m multiport --destination-port $NFS_PORT,$LOCKD_PORT -j LOG --log-prefix "(D)DstAddrCk(CmnPrtsUDP): " 
$IPTABLES -A destination_address_check -p udp -m multiport --destination-port $NFS_PORT,$LOCKD_PORT -j DROP 

#########################################################################################
# Refuse any connections from problem sites
#########################################################################################
# /opt/iptables/rules.blocked.ips.v4 contains a list of
# $IPTABLES -A input -i $INTERNET_IF -s <address/mask> -j DROP
# rules to block all access.
# Refuse packets claiming to be from the banned list
if [ -f /opt/iptables/rules.blocked.ips.v4 ]; then
 	if [ "$RUN_SILENTLY" != "1" ]; then
  		echo "Setting rules for the banned IP list..."
 	fi
 	. /opt/iptables/rules.blocked.ips.v4
fi

#########################################################################################
# Logging Rules Prior to Dropping by the Default Policy
#########################################################################################

######################
# Incoming rules #
######################

##############
# ICMP rules #
##############
#-cap for right now, I'd like to see most of this logged so that I know what rules
# to adjust
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Limit echo requests."
fi

$IPTABLES -A log_in -p icmp ! --icmp-type echo-request -m limit -j LOG --log-prefix "(D)IN-drop: "

##############
# TCP rules #
##############
echo -n "Log all unmatched TCP requests except: "
$IPTABLES -A log_in -p tcp --dport 0:134 -j LOG --log-prefix "(D)IN-drop: "

# Skip Microsoft RPC at 135
echo -n "MS RPC (135)"
$IPTABLES -A log_in -p tcp --dport 136 -j LOG --log-prefix "(D)IN-drop: "

# Skip Microsoft NETBIOS crap at 137, 138, & 139
echo -n ", NetBIOS (137-139)"
#137 netbios-ns NETBIOS Name Service
#138 netbios-dgm NETBIOS Datagram Service
#139 netbios-ssn NETBIOS Session Service
$IPTABLES -A log_in -p tcp --dport 140:142 -j LOG --log-prefix "(D)IN-drop: "

# skip imap
echo -n ", imap (143)"
$IPTABLES -A log_in -p tcp --dport 144:444 -j LOG --log-prefix "(D)IN-drop: "

# skip microsoft-ds
echo ", & MS-DS (444)"
$IPTABLES -A log_in -p tcp --dport 446:65535 -j LOG --log-prefix "(D)IN-drop: "

##############
# UDP rules #
##############
echo -n "Log all unmatched UDP requests except: "
$IPTABLES -A log_in -p udp ! -d $BROADCAST_DEST --dport 0:136 -j LOG --log-prefix "(D)IN-drop: "
# Skip Microsoft NETBIOS crap at 137, 138, & 139
echo "NetBIOS (137-139)"
#137 netbios-ns NETBIOS Name Service
#138 netbios-dgm NETBIOS Datagram Service
#139 netbios-ssn NETBIOS Session Service

echo "Log broadcast requests (up to a limit) "
$IPTABLES -A log_in -p udp ! -d $BROADCAST_DEST --dport 140:65535 -m limit --limit 1/sec -j LOG --log-prefix "(D)IN-drop: "

######################
# Outgoing rules #
######################
# Don't log rejected outgoing ICMP destination-unreachable packets
echo "Don't log rejected outgoing ICMP destination-unreachable packets "
$IPTABLES -A log_out -p icmp --icmp-type destination-unreachable -j LOG --log-prefix "(D)OUT-icmp-dest-unrch-drop: "
$IPTABLES -A log_out -p icmp --icmp-type destination-unreachable -j DROP


echo "Log everything else "
# But log everything else
$IPTABLES -A log_out -j LOG --log-prefix "(D)OUT-drop: "

######################
# Forward rules #
######################
# But log everything else
$IPTABLES -A log_forward -j LOG --log-uid --log-prefix "(D)FWD-drop: "

#########################################################################################
# NAT rules
#########################################################################################
# Packets being forwarded from our internal machines being NATed before being sent
# to the Internet
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "NAT rules: "
fi
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "SNAT "
fi
$IPTABLES -t nat -A POSTROUTING -o $INTERNET_IF -j SNAT --to-source $INTERNET_IP

#########################################################################################
# Set up the jumps from the built-in INPUT, OUTPUT, and FORWARD chains to our standard 
# user chains
#########################################################################################
# If TCP: Check for common stealth scan TCP state patterns
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Creating the jump rules to the user-defined chains:"
fi
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n " TCP state, "
fi
$IPTABLES -A INPUT -p tcp -j tcp_state_flags
$IPTABLES -A OUTPUT -p tcp -j tcp_state_flags
$IPTABLES -A FORWARD -p tcp -j tcp_state_flags
# If we are doing connection tracking, we can bypass a lot of checks
if [ "$USE_CONNECTION_TRACKING" = "1" ]; then
 	if [ "$RUN_SILENTLY" != "1" ]; then
  		echo -n "conn track, "
 	fi
 	# By-pass the firewall filters for established exchanges
	$IPTABLES -A INPUT -j connection_tracking
	$IPTABLES -A OUTPUT -j connection_tracking
	$IPTABLES -A FORWARD -j connection_tracking
fi

# DHCP Client (when this F/W is a DHCP client to an ISP's DHCP server)
if [ "$ISA_DHCP_CLIENT" = "1" ]; then
 	if [ "$RUN_SILENTLY" != "1" ]; then
  		echo -n "DHCP client, "
 	fi
	$IPTABLES -A INPUT -i $INTERNET_IF -p udp --sport bootps --dport bootpc -j rmt_dhcp_srv_response
	$IPTABLES -A OUTPUT -o $INTERNET_IF -p udp --sport bootpc --dport bootps -j lcl_dhcp_client_query
fi

# DHCP Server (when this F/W is a DHCP server to the internal LAN)
if [ "$ISA_DHCP_SERVER" = "1" ]; then
 	if [ "$RUN_SILENTLY" != "1" ]; then
  		echo -n "DHCP server, "
 	fi
	$IPTABLES -A INPUT -i $LAN_IF -p udp --sport bootpc --dport bootps -j LAN_dhcp_client_query
	$IPTABLES -A OUTPUT -o $LAN_IF -p udp --sport bootps --dport bootpc -j LAN_dhcp_srv_response
	$IPTABLES -A INPUT -i $LAN_IF -p udp --sport 21302 --dport 21302 -j LAN_dhcp_client_query
	$IPTABLES -A OUTPUT -o $LAN_IF -p udp --sport 21302 --dport 21302 -j LAN_dhcp_srv_response
fi

# Test for illegal source and destination addresses in incoming packets
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "source addr check, "
fi
$IPTABLES -A INPUT ! -p tcp -i $INTERNET_IF ! -s $LAN_SUBNET -j source_address_check
$IPTABLES -A INPUT -p tcp --syn -i $INTERNET_IF ! -s $LAN_SUBNET -j source_address_check
$IPTABLES -A FORWARD ! -p tcp -i $INTERNET_IF ! -s $LAN_SUBNET -j source_address_check
$IPTABLES -A FORWARD -p tcp --syn -i $INTERNET_IF ! -s $LAN_SUBNET -j source_address_check

# Test for illegal destination addresses in incoming packets
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "dest addr check, "
fi

# Test for illegal destination addresses in incoming packets
$IPTABLES -A INPUT -j destination_address_check

# Test for illegal destination addresses in outgoing packets
$IPTABLES -A OUTPUT -j destination_address_check

# Test for illegal destination addresses in forwarded packets
$IPTABLES -A FORWARD -j destination_address_check
# Begin standard firewall tests for packets addressed to this host

# Packets coming from the Internet that are destined to us 
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n " ext if in, "
fi
$IPTABLES -A INPUT -i $INTERNET_IF -d $INTERNET_IP -j ext_if_in

# Packets coming from our interal LAN destined to the LAN IP Address
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "LAN if in, "
fi
$IPTABLES -A INPUT -i $LAN_IF -d $LAN_IP -j lan_if_in

# Packets coming from our interal LAN destined to the Multicast Address
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "LAN if multicast in, "
fi
$IPTABLES -A INPUT -i $LAN_IF -d $CLASS_D_MULTICAST -j lan_if_multi_in

# Packets being forwarded from the Internet to our internal LAN
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ext -> int, "
fi
$IPTABLES -A FORWARD -i $INTERNET_IF -o $LAN_IF -j ext_int

# Packets being forwarded from our internal LAN to our external IP address
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "LAN -> ext if, "
fi
$IPTABLES -A INPUT -i $LAN_IF -d $INTERNET_IP -j ext_if_lan_in

# Begin standard firewall tests for packets sent from this host
# Source address spoofing by this host is not allowed due to the
# test on source address in this rule.
# Packets generated from our external IP address destined to addresses on the Internet
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "ext if out, "
fi
$IPTABLES -A OUTPUT -o $INTERNET_IF -s $INTERNET_IP -j ext_if_out

# Packets generated from our LAN IP Address destined to the interal LAN
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "LAN if out, "
fi
$IPTABLES -A OUTPUT -o $LAN_IF -s $LAN_IP -j lan_if_out

# Packets generated from our LAN IP Address destined to the interal LAN
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "LAN if multicast out, "
fi
$IPTABLES -A OUTPUT -o $LAN_IF -s $CLASS_D_MULTICAST -j lan_if_multi_out

# Packets being forwarded from our internal LAN to the Internet
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n " int -> ext, "
fi
$IPTABLES -A FORWARD -i $LAN_IF -o $INTERNET_IF -j int_ext

# Packets being forwarded from our external IP address to our internal LAN
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& ext if -> LAN, "
fi
$IPTABLES -A OUTPUT -o $LAN_IF -s $INTERNET_IP -j ext_if_lan_out


#############################################
# Log anything of interest that fell through,
# before the default policy drops the packet.
#############################################
$IPTABLES -A INPUT -j log_in 
$IPTABLES -A OUTPUT -j log_out 
$IPTABLES -A FORWARD -j log_forward


#########################################################################################
# Open up the flood gates
#########################################################################################
if [ "$RUN_SILENTLY" != "1" ]; then
	echo " "
	echo -n "Restoring normal traffic: "
 	logger "$(basename "$0"): Rules applied. Restoring normal traffic."
fi
if [ "$RUN_SILENTLY" != "1" ]; then
	echo -n "INPUT chain "
fi
$IPTABLES -D INPUT 1
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "& FORWARD chain. "
fi
$IPTABLES -D FORWARD 1
if [ "$RUN_SILENTLY" != "1" ]; then
	echo "Turn on IP forwarding. "
fi
echo 1 > /proc/sys/net/ipv4/ip_forward

if [ "$RUN_SILENTLY" != "1" ]; then
	echo "done at:" `date`
 	logger "$(basename "$0"): Done."
fi

# iptables-save > iptables.save.atEnd.txt

exit 0

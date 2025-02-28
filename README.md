
# ipv6-router-scripts Project

# Introduction:

This project has several bash scripts that I use with Verizon Fios Internet to set up and maintain IPv6 functionality. It also touches on the IPv4 setup I have, but to a lesser degree. Verizon's IPv6 implementation delegates a /56 prefix and nothing else. It is up to the router/firewall to divide the delegated prefix into (up to 256) internal LANs and external WANs. The goals of these scripts are:

- Based on the delegated /56 prefix:
	- Create a /64 subnet and assign the first IP in that subnet to the WAN interface
	- Create a second /64 subnet and assign the first IP in that subnet to the LAN interface
- Use the IPv4 and IPv6 IP addresses assigned to the LAN interface to:
	- Establish the firewall rules for IPv4 traffic
	- Establish the firewall rules for IPv6 traffic Configure the :


I have what I like to think is a rigorous set of firewall rules that are keyed to LAN IP addresses handed out by DHCP4 and DHCP6 servers.

Scripts that use a delegated prefix to set WAN and LAP IPv6, firewall rules, DNS, and DHCP on a Linux router/firewall
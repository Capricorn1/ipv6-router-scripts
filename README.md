# ipv6-router-scripts Project

# Introduction:

This project includes several bash scripts I use with Verizon Fios Internet to set up and maintain IPv6 functionality for a homemade firewall/router. It also touches on my IPv4 configuration, but to a lesser degree. These run on a relatively low-performance Intel-based PC (or mini-PC) using the Ubuntu Linux distro, which currently has version 24.04.2 LTS.

Verizon's IPv6 implementation delegates a /56 prefix and nothing else. It is up to the router/firewall to divide the delegated prefix into (up to 256) internal LANs and external WANs. The goals of these scripts are:

*   Set the IPv6 Subnets and IP addresses for the WAN and LAN based on the delegated /56 prefix:
    
    *   Create a /64 subnet and assign the first IP in that subnet to the WAN interface
        
    *   Create a second /64 subnet and assign the first IP in that subnet to the LAN interface
        
*   Set the firewall ruleset by using the LAN-side IPv4 and IPv6 IP addresses to:
    
    *   Establish the firewall rules for IPv4 traffic
        
    *   Establish the firewall rules for IPv6 traffic
        
*   Use the LAN IPv6 subnet and IP address to configure the DHCP6 server:
    # ipv6-router-scripts Project

# Introduction:

This project includes several bash scripts I use with Verizon Fios Internet to set up and maintain IPv6 functionality for a homemade firewall/router. It also touches on my IPv4 configuration, but to a lesser degree. These run on a relatively low-performance Intel-based PC (or mini-PC) using the Ubuntu Linux distro, which currently has version 24.04.2 LTS. These scripts expect systemd-networkd as the network manager (as opposed to NetworkManager).

Verizon's IPv6 implementation delegates a /56 prefix and nothing else. It is up to the router/firewall to divide the delegated prefix into (up to 256) internal LANs and external WANs. The goals of these scripts are:

*   Set the IPv6 Subnets and IP addresses for the WAN and LAN based on the delegated /56 prefix:
    
    *   Create a /64 subnet and assign the first IP in that subnet to the WAN interface
        
    *   Create a second /64 subnet and assign the first IP in that subnet to the LAN interface
        
*   Set the firewall ruleset by using the LAN-side IPv4 and IPv6 IP addresses to:
    
    *   Establish the firewall rules for IPv4 traffic
        
    *   Establish the firewall rules for IPv6 traffic
        
*   Use the LAN IPv6 subnet and IP address to configure the DHCP6 server:
    
    *   Edit a DHCP6 template with the subnet and IP address
        
    *   (Re-)Start the DHCP6 server
        
*   Use the LAN IPv6 subnet and IP address to configure a local caching DNS server
    
    *   Edit templates for the db.home.zone, db.reverse.ipv6.zone, and the named.conf.local files
        
    *   (Re-)Start the DNS server
        

The delegated prefix from Verizon could change every time the DHCP lease expires or when the network is restarted (by rebooting the router or performing an update that updates the networking system). Therefore, we need a way to intercept such changes and update our IPs and LAN-side DHCP and DNS services to match. (As a bonus, there is a way to minimize the number of times Verizon assigns a new delegated prefix by not releasing it when rebooting. It's not a script; it's a network configuration file. A sample is included in this project.)

# Impetus

I think I have a rigorous set of firewall rules for IPv4 that I have honed over the last 20 years. The rules depend on the LAN IP addresses distributed by the DHCP server. The IP addresses are assigned by the device's MAC address and grant well-defined port access to specific machines. These include inbound and outbound rules. I have included a subset of my complete set (with editing to sanitize them). With IPv4, setting up these rules was straightforward because I chose the LAN subnet and used NAT to map that subnet to the single IPv4 address assigned to the router. The LAN configuration did not change when the external WAN IP changed (which it rarely did). When I started to support IPv6, the consensus was that it was **Bad®** to use NAT when an entire IPv6 /56 prefix is delegated to every customer. That's great, but since the LAN (and WAN) subnet changes every time the prefix changes, _hardcoding_ the LAN configuration for DHCP and DNS is impossible. Since I wanted to be able to apply the firewall rules for IPv6 in the same manner, I needed to be flexible about how those services get configured.

# Project Structure

The project structure is set up to mimic the location of the files relative to the root (/) directory. The first two directories are `etc` and `opt`, and the files within those directories should be installed in the `/etc` and `/opt` directories, respectively. If the /opt directory did not previously exist, it should be created with root as the owner and group and with 755 (or 775) for the access mode. The following code block shows the ownership and permissions for the directories in which files from this project should be placed.

```javascript
root@fw2404:/# ls -ld /etc /etc/bind /etc/netplan /etc/networkd-dispatcher /etc/networkd-dispatcher/routable.d /etc/systemd \
> /etc/systemd/network /etc/systemd/network/10-netplan-enp2s0.network.d /opt /opt/iptables /opt/ipv6-configuration
drwxr-xr-x 144 root root 12288 Feb 27 09:06 /etc
drwxr-sr-x   2 root bind  4096 Feb 27 16:23 /etc/bind
drwxr-xr-x   2 root root  4096 Feb 27 09:34 /etc/netplan
drwxr-xr-x   8 root root  4096 Aug 27  2024 /etc/networkd-dispatcher
drwxr-xr-x   2 root root  4096 Feb 13 10:08 /etc/networkd-dispatcher/routable.d
drwxr-xr-x   6 root root  4096 Feb  7 16:59 /etc/systemd
drwxr-xr-x   3 root root  4096 Feb  8 12:22 /etc/systemd/network
drwxr-xr-x   2 root root  4096 Feb  8 11:47 /etc/systemd/network/10-netplan-enp2s0.network.d
drwxr-xr-x   7 root root  4096 Feb 13 07:24 /opt
drwxr-xr-x   2 root root  4096 Feb 25 16:27 /opt/iptables
drwxr-xr-x   2 root root  4096 Feb 14 14:01 /opt/ipv6-configuration

```

Examine each of the subdirectories listed above for documenation of the files in that directory.
    *   Edit a DHCP6 template with the subnet and IP address
        
    *   (Re-)Start the DHCP6 server
        
*   Use the LAN IPv6 subnet and IP address to configure a local caching DNS server
    
    *   Edit templates for the db.home.zone, db.reverse.ipv6.zone, and the named.conf.local files
        
    *   (Re-)Start the DNS server
        

The delegated prefix from Verizon could change every time the DHCP lease expires or when the network is restarted (by rebooting the router or performing an update that updates the networking system). Therefore, we need a way to intercept such changes and update our IPs and LAN-side DHCP and DNS services to match. (As a bonus, there is a way to minimize the number of times Verizon assigns a new delegated prefix by not releasing it when rebooting. It's not a script; it's a network configuration file. A sample is included in this project.)

# Impetus

I think I have a rigorous set of firewall rules for IPv4 that I have honed over the last 20 years. The rules depend on the LAN IP addresses distributed by the DHCP server. The IP addresses are assigned by the device's MAC address and grant well-defined port access to specific machines. These include inbound and outbound rules. I have included a subset of my complete set (with editing to sanitize them). With IPv4, setting up these rules was straightforward because I chose the LAN subnet and used NAT to map that subnet to the single IPv4 address assigned to the router. The LAN configuration did not change when the external WAN IP changed (which it rarely did). When I started to support IPv6, the consensus was that it was **Bad®** to use NAT when an entire IPv6 /56 prefix is delegated to every customer. That's great, but since the LAN (and WAN) subnet changes every time the prefix changes, _hardcoding_ the LAN configuration for DHCP and DNS is impossible. Since I wanted to be able to apply the firewall rules for IPv6 in the same manner, I needed to be flexible about how those services get configured.

# Project Structure

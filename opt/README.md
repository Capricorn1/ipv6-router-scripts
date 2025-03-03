# opt Directory

# Structure and Contents

The files in this directory are expected to be installed in their corresponding directories in the /opt directory. The /opt directory may not exist. If it does not, create it with root as the owner and group and 755 as the access mode. The subdirectories include:

*   iptables: Contains scripts with iptables rulesets for IPv4 and IPv6 traffic.

*   IPv6-configuration: This contains both bash scripts and the templates those scripts operate on. The scripts set the WAN and LAN IP addresses for IPv6, configure the DHCP6 server, and configure the local caching DNS server.

# Details

## The iptables Directory

This directory contains two scripts that set the firewall rules for IPv4 and IPv6 traffic and two auxiliary files that contain a list of IP addresses permanently blocked from accessing this firewall. The scripts use iptables and ip6tables, respectively. Unlike most commercial home firewalls (e.g., Netgear Nighthawk or Verizon CR1000A), this firewall restricts incoming and outgoing traffic.

**Disclaimer:** These scripts are a subset of my actual ruleset. They have been significantly edited and sanitized for your (my) protection. These have not been run to make sure they are correct. They may (and probably do) contain errors. I also make no claims that this is the best way to write firewall rules, but it has worked for me for years. YMMV.

### The rules-dhcp-ip-from-shell.v4.sh File

The `rules-dhcp-ip-from-shell.v4.sh` file contains the ruleset for IPv4 traffic. It assumes that the IPv4 subnet is 192.168.115.0/24 (to match the other example files). Many parts of the script should work for most environments. The parts that will vary are the sections labeled *Other Internal Servers & Ports*, the user chains, and the device-specific rules like the *Specific rules for VPN and services* and *Rules for guest gaming desktop*. 

The Other Internal Servers & Ports list includes devices that may require special rules. Changes or additions made here must be correlated with the `db.home.zone.template`, `db.reverse.ipv6.arpa.zone.template`, and `kea-dhcp6.conf.template` files in the `opt/ipv6-configuration/` directory.

The USER_CHAINS section defines rule chains for individual devices, classes of devices, and groups types of Internet traffic. For example, a pair of chains for a gaming PC - gaming_pc_in and gaming_pc_out - contain the firewall rules for traffic coming into and going out from the gaming PC, respectively. Another pair of chains - smartplugswitch_in and smartplugswitch_out - have grouped rules for smart plugs and switches. Another chain, the lcl_dns_srv_to_trust_dns_srv chain, is used for rules from our local caching DNS server to our ISP's DNS servers and other trusted DNS servers on the internet.

### The rules-dhcp-ip-from-shell.v6.sh File

Analogous to the `rules-dhcp-ip-from-shell.v4.sh` file, the `rules-dhcp-ip-from-shell.v6.sh` file contains rules for IPv6 traffic. This script has separate sections for link-local traffic and regular IPv6 traffic. Unlike the IPv4 script, this script is written to adjust for changing IPv6 subnets on the LAN side. This script uses the `sipcalc` package to create some rules dynamically. The sections of the script mentioned in the rules-dhcp-ip-from-shell.v4.sh section above also apply here. 

### The rules.blocked.ips.v4 and rules.blocked.ips.v6 Files

These files contain iptables and ip6tables rules to block specific IPs. These IPs appear in the firewall logs as repeat offenders attempting to scan ports on the firewall. This is the naughty list.

## The ipv6-configuration Directory

This directory contains the following scripts and templates: 

*   ipv6-compute-and-configure.sh: Script that sets the WAN and LAN IP addresses for IPv6 based on the current prefix delegation received from the upstream DHCP server, Verizon's DHCP server. This script must be successfully completed before the firewall scripts (see above) and other scripts in this directory can be run.

*   dhcp6-server-configure.sh: Edits the `kea-dhcp6.conf.template` with the current LAN IP address and subnet and stores the result in the `/etc/kea folder` as `kea-dhcp6.conf`. It then stops and restarts the Kea DHCP6 service.

*   local-dns-server-configure.sh: Edits the `db.home.zone.template`, `db.reverse.ipv6.arpa.zone.template`, and `named.conf.local.template` files with the current LAN IP address and subnet and stores the results in the `/etc/bind` folder as files of the same name less the `.template` suffix. It then stops and restarts the named (bind9) service.

### The ipv6-compute-and-configure.sh Script

This script sets the WAN and LAN IP addresses for IPv6. It does so by retrieving the current delegated prefix from the routing table. Our (systemd-networkd) DHCP client solicits for the upstream DHCP server, which will resolve to one of Verizon's DHCP servers. As a part of that exchange, we get assigned a prefix delegation. This script must be completed before the firewall scripts (see above) and other scripts in this directory will run successfully. 

The WAN_IF and LAN_IF variables are set to the names of the WAN and LAN interfaces, respectively. (They should match the names the `ip a` command returned.) These may need to be edited for your environment. The script also has a variable for EXPECTED_PREFIX_LENGTH, which is set to *56*. While this is theoretically a variable, the script will likely fail if it is set to any other value.

### The dhcp6-server-configure.sh Script and kea-dhcp6.conf.template File

This `dhcp6-server-configure.sh` script edits a templated version of the DHCP6 configuration file and writes out the result to the configured output path. It has WAN_IF and LAN_IF variables for the WAN and LAN interfaces, respectively. It also has variables indicating where to find the template and where to write the edited version. As the variables are currently set in the project, the template is read from `/opt/ipv6-configuration/kea-dhcp6.conf.template` and stored in `/etc/kea/kea-dhcp6.conf`. This script assumes that the DHCP6 server is the Kea DHCP6 server. The script will need to be modified if another DHCP server is used.

The kea-dhcp6.conf.template file is the template that is edited into the kea-dhcp6.conf file. In my environment, nearly all IP addresses are handled by DHCP reservation. Whenever a new device is added, or an existing one is removed/replaced, the `"reservations" ` section needs to be updated accordingly. The reservations in this example template are all by hardware (MAC) address (hw-address). For example, the entry below would assign the IPv6 address beginning with the current IPv6 subnet and ending with 500.

```
                {
                    "hostname": "steamdeckdock",
                    "hw-address": "00:11:22:aa:bb:01",
                    "ip-addresses": [ "XXXX:XXXX:XXXX:XXXX::500" ]
                },
```
The script will replace the `XXXX:XXXX:XXXX:XXXX` string pattern with the LAN subnet before writing the file to the output path. Changes to the template file should be synchronized with the other template and iptables files.

### The local-dns-server-configure.sh Script and db.home.zone.template, db.reverse.ipv6.arpa.zone.template, and named.conf.local.template Files

The `local-dns-server-configure.sh` script edits the three template scripts with the currently delegated prefix and writes the edited version out to the directory used by the named.service (aka bind 9), typically `/etc/bind`. It has the same WAN_IF and LAN_IF variables for the WAN and LAN interfaces as the previous scripts. There are also script variables for the template names and locations and the edited template directory path and name. After writing out the edited versions of the templates, the script stops and restarts the `named.service`.

The `db.home.zone.template` file contains the DNS definition for the IPv4 and IPv6 addresses for every device in the system. It assumes the IPv4 subnet is `192.168.115.0/24`. That would need to be edited if a different subnet were used for IPv4. The current LAN /64 prefix (as set by the `ipv6-compute-and-configure.sh` script) will replace the `IPV6_PREFIX_64` string pattern. The GENERATED_SERIAL string will be replaced with an increasing serial number based on the current time.

The `db.reverse.ipv6.arpa.zone.template` file contains the reverse DNS PTR records for the IPv6 IP addresses. The PTR records should be updated whenever a new device is added, or an existing one is removed/replaced. The GENERATED_SERIAL string will be replaced with an increasing serial number based on the current time.

The `named.conf.local.template` file contains the names of the zone files to be used with the DNS server. This should not need to be changed for most environments, but it does contain a reference to the IPv4 subnet `192.168.115.0/24`. If a different subnet is to be used, two strings in the zone `115.168.192.in-addr.arpa` entry.

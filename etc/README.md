# etc Directory

# Structure and Contents

The files in this directory are expected to be installed in their corresponding directories in the /etc directory. They include:

*   bind: The portions of the DNS (named.service) configuration that do not change when the IPv6 prefix changes. They can be treated as "fixed" files and are included here only to present a complete example. Files like db.0, db.empty, and zones.rfc1918 are created during the installation of bind9 and are not included in this example.

*   netplan: Includes an example YAML file for network configuration that ties in with the rest of the example. Notably, it defines the interfaces and that the (systemd-)networkd renderer is used.

*   networkd-dispatcher: Contains the routable.d directory of "parent" scripts that, in turn, run scripts from the opt (/opt) directory when the routable network status changes. These scripts run in order by name whenever the system is booted, the DHCP lease from Verizon expires, or some other condition may have caused the delegated prefix to change.

*   systemd: Exists only to house the network/10-netplan-enp2s0.network.d/override.conf directories and lone file. The override.conf file contains the `SendRelease-false` DHCPv6 directive to NOT release the delegated prefix when the WAN interface is restarted. This results in the same delegated prefix being returned by Verizon's DHCP6 server for an extended period.

# Details

## The bind Directory

The bind directory in this project contains files for configuring the DNS (named.service) that are **not** dependent on the currently delegated prefix. The files may need to be edited once for a specific environment, but should not require editing after that. The directory contains the files `db.115.168.192.in-addr.arpa.zone`, `named.conf`, and `named.conf.options`. This assumes that the LAN subnet is `192.168.115.0/24`. If this is not the subnet of your LAN, edit the name of the db.115.x file and the `(/)opt/ipv6-configuration/db.home.zone.template` and `(/)opt/ipv6-configuration/named.conf.local.template` to the correct subnet. At the time of this writing, the version of bind9 is `1:9.18.30-0ubuntu0.24.04.2`. 

## The netplan Directory

The project's netplan directory contains an example network configuration YAML file, `10-networkd-all.yaml`. It contains a typical router/firewall network definition with two Ethernet interfaces. These are the enp2s0 (the WAN interface) and the enp4s0 (the LAN interface) for this example, but those need to be edited to match the interfaces of your environment.
```
# This file sets the basic networking information for the our firewall/router
# enp2s0 is the WAN interface
# Our IPv4 LAN is on the 192.168.115.0/24 subnet
network:
  renderer: networkd
  ethernets:
    enp2s0:
      link-local: [ ipv6 ]
      dhcp4: true
      dhcp6: true
      accept-ra: true
      ipv6-privacy: false
      nameservers:
        addresses: [8.8.8.8,8.8.4.4,1.1.1.1,"2001:4860:4860::8888","2001:4860:4860::8844"]
    enp4s0:
      link-local: [ ipv6 ]
      dhcp4: false
      dhcp6: false
      addresses: [192.168.115.1/24,"2600:4040:4026:301:0:0:0:1/64"]
      accept-ra: false
      ipv6-privacy: false
      nameservers:
        addresses: [192.168.115.1,8.8.8.8,8.8.4.4,"2001:4860:4860::8888","2001:4860:4860::8844"]
        search: [ home ]
  version: 2
```
The name of this file is arbitrary, but it will be used to create runtime network configuration by NetPlan whenever the system is (re)booted or the network is restarted (such as when the network daemons are upgraded).

## The networkd-dispatcher Directory

This directory contains the `routable.d` subdirectory. The scripts in that subdirectory are meant to be copied into the actual `/etc/networkd-dispatcher/routable.d` directory. The `networkd-dispatcher.service` calls the scripts in that directory (in order by name) when the network state enters the routable state. For IPv6 networking, this occurs when a prefix is delegated, such as when the router is rebooted or `netplan apply` is executed. These are "parent" scripts that, in turn, call scripts in the `(/)opt/ipv6-configuration` directory to configure the IPv6 WAN and LAN IP addresses, the IPv4 and IPv6 firewall rules, the DHCP6 configuration, and the DNS configuration. These scripts check to make sure they are being called when the WAN interface becomes routable. Otherwise, the scripts would be call twice - once for the LAN and WAN interfaces becoming routable. On my system, the LAN interface becomes routable before the WAN interface (and before the prefix delegation has occurred). The script names and order in which the scripts are run is:
```
root@fw2404:~/Projects/ipv6-router-scripts/etc/networkd-dispatcher/routable.d$ ll
total 20
-rwxrwxr-x 1 cap cap 1304 Feb 27 20:40 10-ipv6-configure.sh*
-rwxrwxr-x 1 cap cap 1066 Feb 27 20:40 50-ipv4-rules-on-routable.sh*
-rwxrwxr-x 1 cap cap 1069 Feb 27 20:40 51-ipv6-rules-on-routable.sh*
-rwxrwxr-x 1 cap cap 1165 Feb 27 20:40 98-ipv6-dhcp-server-configure.sh*
-rwxrwxr-x 1 cap cap 1164 Feb 27 20:40 99-ipv6-dns-server-configure.sh*
```

## The systemd Directory

This directory does not contain bash scripts. Instead it contains one configuration file that sets the `SendRelease=false` parameter for the DHCPv6 client that talks to the Verizon DHCP6 server. That parameter tells our DHCP client to not send the release directive (DHCPRELEASE) when the WAN interface is shut down and restarted. For some time period, our router will get the same because this is set. It is not guaranteed to be the same forever, but since setting this parameter my router has gotten the same prefix delegation for months.

The netplan directory section above mentioned that Netplan creates runtime files that are based on the name and contents of the YAML configuration file. In our example, the directories are found in the `/run/systemd/network` directory as the files `10-netplan-enp2s0.network` and `10-netplan-enp4s0.network`.


```
root@fw2404:/run/systemd/network# ll
total 8
-rw-r----- 1 root systemd-network 204 Feb 27 09:06 10-netplan-enp2s0.network
-rw-r----- 1 root systemd-network 236 Feb 27 09:06 10-netplan-enp4s0.network
```

We want to override the enp2s0 interface's DHCPv6 parameters (since that is our WAN interface). The file created by Netplan contains:

```
root@fw2404:/run/systemd/network# more 10-netplan-enp2s0.network
[Match]
Name=enp2s0

[Network]
DHCP=yes
LinkLocalAddressing=ipv6
IPv6AcceptRA=yes
DNS=8.8.8.8
DNS=8.8.4.4
DNS=1.1.1.1
DNS=2001:4860:4860::8888
DNS=2001:4860:4860::8844

[DHCP]
RouteMetric=100
UseMTU=true
```
The name of the subdirectory where we place the override configuration file is not arbitrary. In our example, the `etc/systemd/network/10-netplan-enp2s0.network.d/override.conf` file would be copied into the /etc directory with intermediate directories created as needed. The `/etc/systemd/network portion` is fixed, however, the `10-netplan-enp2s0.network.d` subdirectory must match the name of the runtime file (for the interface we are overriding) in `/run/systemd/network` with a `.d` appended. Any files in that directory that end with `.conf` will be read and merged with the ones in the run directory. The systemd.network man page lists other potential locations and file names for containing override parameters, but the .d directory with an *.conf file seems to be the only reliable way. The contents of the override file are:

```
root@fw2404:~/Projects/ipv6-router-scripts/etc/systemd/network/10-netplan-enp2s0.network.d$ more override.conf
[Match]
Name=enp2s0

[DHCPv6]
SendRelease=false
```

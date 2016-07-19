#DHCProbe -- send a DHCP request to DHCP server to check its configuration
==========================================================================

Using DHCProbe, one can request a lease from a DHCP server, 
and dump the result for verifying the configuration.

Example in verbose mode:

	 $ sudo ./dhcprobe -v -s 172.20.205.1
	Got answer from: 172.20.205.1
	option 53 DHCP message type 6 (DHCPNAK)
	option 54 Server identifier 172.20.205.1
	option  1 Subnet mask 255.255.255.0
	option  3 Router 172.20.205.1
	option 15 Domain name slh.local
	option  6 DNS server 172.20.200.250
	option 51 IP address leasetime 
	option 58 T1 
	option 59 T2 


We can verify that the domain name, DNS server, etc. are configured correctly
in the DHCP server.

Build Instructions
------------------

       ./autogen.sh
       ./configure
       make
       make install


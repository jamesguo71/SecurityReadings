# Network Security Reading: Lab 1 Sniffing and Spoofying

## Fei Guo, 2022-06-30

## Task 1.1A Sniffing Packets

Running Scapy python scripts for sniffing without root privilege will get a `PermissionError: [Errno 1] Operation not permitted`.

One of the reasons we need root privilege for this is that we need to compile BPF and put it in kernel before executing.

## Task 1.1B Sniffing Packets

Write BPF rules for capturing packets:

• Capture only the ICMP packet
	"icmp"

• Capture any TCP packet that comes from a particular IP and with a destination port number 23.
	"tcp dst port 23 and ip src host <ip>"

• Capture packets comes from or to go to a particular subnet. You can pick any subnet, such as 128.230.0.0/16; you should not pick the subnet that your VM is attached to.
	"net 203.107"

## Task 1.2 Spoofing ICMP Packets

Here is how I conduct the ICMP packet spoofing.

On 10.9.0.5 (machine C), Spoof an ICMP packet from '10.9.0.6' (machine B) like this:

```
send( IP(src='10.9.0.2', dst='8.8.8.8') / ICMP() )
```

Then I can sit on another host, 10.9.0.1 (machine A), and using WireShark in Promiscuous Mode, sniff the echo request sent from C, and the echo reply sent from '8.8.8.8' to machine B (not machine C, where I actually sent the packet).

## Task 1.3 Traceroute

Use Scapy to implemenet `traceroute`:
```
def traceroute(hostname):
	hop = 1
	while True:
		# Unix typically sends UDP packets for probing
		reply = sr1(IP(dst=hostname, ttl=hop)/ UDP(dport=33434), verbose=0, timeout=3) 
		if not reply:
			# We didn't get a reply, this may happen because the server at this hop just didn't configure ICMP. But this doesn't mean we shouldn't move on
			print("* * *") # mimic the traceroute behavior
		elif reply.type == 3:
			print("Destination reached!")
			break
		else:
			print(hop, "hops away", reply.src)
		hop += 1

hostname = "twitter.com"
traceroute(hostname)

```

## Task 1.4: Sniffing and-then Spoofing

Running this script to spoof ICMP echo request on a machine in a LAN and ping 1.2.3.4 (an invalid IP on the Internet) from another machine in the same LAN, the ping would succeed!

```
#!/usr/bin/env python3
from scapy.all import *
def spoofer(pkt):
	# Only dealing with ICMP ECHO REQUEST, so that we won't be handling the spoofed ones we send out!
    if pkt[ICMP].type != 8:
    	return
    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
    icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
    data = pkt[RAW].load
    send(ip/icmp/data)

myfilter = "icmp"
sniff(iface=['eth0', 'br-e0925ad990c9'], filter=myfilter, prn=spoofer)
```

If we change the "dst host 1.2.3.4" above to "dst host 10.9.0.99" and ping 10.9.0.99, we would get a DESTINATION UNREACHABLE error from the ping. Also, we can't even see sniff the ICMP request from the attach machine. Why is this the case? This is related to ARP protocol. 10.9.0.99 is a reserved private address, so when we ping this address, we will be using ARP for getting the MAC address of the potential machine (instead of sending out the packet from the LAN). Since 10.9.0.99 doesn't exist in our local LAN, it will fail and get a DESTINATION UNREACHABLE error before sending out the ICMP echo request, which is why we wouldn't even succeed in sniffing the ICMP request.

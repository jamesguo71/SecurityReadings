# VPN Tunneling Lab

## Lab Link: https://seedsecuritylabs.org/Labs_20.04/Networking/VPN_Tunnel/

## Create and Configure TUN Interface

TUN and TAP are virtual network kernel drivers; they implement network device that are supported entirely in software.

### Create the TUN interface

The code below will create a new TUN interface.

File: `tun.py`

```python
#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

while True:   
   # Get a packet from the tun interface
	packet = os.read(tun, 2048)
	if packet:
		ip = IP(packet)
		print(ip.summary())
	# Send out a spoof packet using the tun interface
	newip = IP(src=’1.2.3.4’, dst=ip.src)
	newpkt = newip/ip.payload
	os.write(tun, bytes(newpkt))
```

```bash
// Make the Python program executable
chmod a+x tun.py
// Run the program using the root privilege
sudo tun.py
```

### Set up the TUN Interface

```bash
// Assign IP address to the interface
# ip addr add 192.168.53.99/24 dev tun0

// Bring up the interface
# ip link set dev tun0 up
```

Or we can do it in Python:
```bash
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
```

### Read from the TUN Interface

> Whatever coming out from the TUN interface is an IP packet. We can cast the data received from the interface into a Scapy IP object, so we can print out each field of the IP packet.

See the `while True` loop above.

### Write to the TUN Interfac

> Since this is a virtual network interface, whatever is written to the interface by the application will appear in the kernel as an IP packet.

##  Send the IP Packet to VPN Server Through a Tunnel

> In this task, we will put the IP packet received from the TUN interface into the UDP payload field of a new IP packet, and send it to another computer. Namely, we place the original packet inside a new packet. This is called IP tunneling. 

`tun_server.py`

```python
#!/usr/bin/env python3
from scapy.all import *
IP_A = "0.0.0.0"
PORT = 9090
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))
while True:
	data, (ip, port) = sock.recvfrom(2048)
	print("{}:{} --> {}:{}".format(ip, port, IP_A, PORT))
	pkt = IP(data)
	print(" Inside: {} --> {}".format(pkt.src, pkt.dst))
```

`tun_client.py`

```python
#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:   
   # Get a packet from the tun interface
	packet = os.read(tun, 2048)	
	if packet:
		# Send the packet via the tunnel
		sock.sendto(packet, (SERVER_IP, SERVER_PORT))
```

> Note, in order for the packet to be sent to VPN Server through the tunnel, we need to set up the routing, i.e., packets going to the 192.168.60.0/24 network should be routed to the TUN interface and be given to the tun client.py program.

```bash
$ ip route add <network> dev <interface> via <router ip>
```

## Set Up the VPN Server

> After tun server.py gets a packet from the tunnel, it needs to feed the packet to the kernel, so the kernel can route the packet towards its final destination.

So `tun_server.py` should be able to:

- Create a TUN interface and configure it.
- Get the data from the socket interface; treat the received data as an IP packet.
- Write the packet to the TUN interface.

Note that we have enable IP forwarding on the router container.

## Handling Traffic in Both Directions

> To handle traffic in both directions, our TUN client and server programs need to read data from two interfaces, the TUN interface and the socket interface. All these interfaces are represented by file descriptors, so we need to monitor them to see whether there are data coming from them. 

Linux has a system call called select(), which allows a program to monitor multiple file descriptors simultaneously.


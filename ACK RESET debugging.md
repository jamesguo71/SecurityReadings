If I drop the packets from a subnet on my Linux instance, which we call "Server", with IP address 10.9.0.1:

`sudo iptables -A INPUT -s 10.9.0.1/24 -p tcp -j DROP`

and then try to connect to the server from HostA of IP 10.9.0.11, and dump the traffic:

```
tcpdump -i eth0 host 10.9.0.1

19:45:19.319694 IP 76993827d082.57866 > ip-10-9-0-1.ec2.internal.http: Flags [S], seq 3452272372, win 64240, options [mss 1460,sackOK,TS val 2745830911 ecr 0,nop,wscale 7], length 0
19:45:20.330084 IP 76993827d082.57866 > ip-10-9-0-1.ec2.internal.http: Flags [S], seq 3452272372, win 64240, options [mss 1460,sackOK,TS val 2745831922 ecr 0,nop,wscale 7], length 0
19:45:22.346085 IP 76993827d082.57866 > ip-10-9-0-1.ec2.internal.http: Flags [S], seq 3452272372, win 64240, options [mss 1460,sackOK,TS val 2745833938 ecr 0,nop,wscale 7], length 0

19:45:24.330070 ARP, Request who-has ip-10-9-0-1.ec2.internal tell 76993827d082, length 28
19:45:24.330122 ARP, Reply ip-10-9-0-1.ec2.internal is-at 02:42:72:c2:ce:32 (oui Unknown), length 28

19:45:26.378078 IP 76993827d082.57866 > ip-10-9-0-1.ec2.internal.http: Flags [S], seq 3452272372, win 64240, options [mss 1460,sackOK,TS val 2745837970 ecr 0,nop,wscale 7], length 0
```

We can see that hostA will *not* receive any response from the server, which matches your previous comment.




TCP is different; because of it's stateful nature and control flags, it is able to indicate a closed port on its own by sending a packet back with the reset ("RST") bit set.
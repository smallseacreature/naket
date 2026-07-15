from database import *
from scapy.utils import PcapReader
from scapy.packet import Packet
from layers import *
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from utils import *

def process_packet(packet: Packet) -> dict:
    # Process the packet from the outside in

    packet_data = {}

    if packet.haslayer(Ether):
        packet_data.update(process_ether_layer(packet[Ether]))

    if packet.haslayer(IP):
        packet_data.update(process_ip_layer(packet[IP]))

    if packet.haslayer(UDP):
        packet_data.update(process_udp_layer(packet[UDP]))

    if packet.haslayer(Raw):
        raw_data = process_raw_layer(packet[Raw])

        if raw_data is not None:
            packet_data.update(raw_data)
        
    return packet_data

def process_pcap(filename: str) -> None:
    with PcapReader(filename) as pcap:
        for packet in pcap:
            packet_data = process_packet(packet)
            print_dictionary(packet_data)

def main():
    
    process_pcap("2026-07-14_10-22-52.pcap")


if __name__ == "__main__":
    main()
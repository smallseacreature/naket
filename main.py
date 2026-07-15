from database import *
from scapy.utils import PcapReader
from scapy.packet import Packet
from layers import *
from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

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
        packet_data.update(process_raw_layer(packet[Raw]))
        
    return packet_data

def process_pcap(filename: str) -> None:
    with PcapReader(filename) as pcap:
        for packet in pcap:
            process_packet(packet)

def main():
    
    #---Database init--
    connection = initialize_database()
    cursor = connection.cursor()

    

if __name__ == "__main__":
    main()
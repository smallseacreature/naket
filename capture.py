from scapy.all import PcapReader


#Gather the data from the pcap for insertion into the database


def get_first_last_packet(filename: str) -> dict:

    """
    Get the timestamps for the first and last packets
    """
    first_packet = None
    last_packet = None

    with PcapReader(filename) as packets:
        for packet in packets:
            if first_packet is None:
                first_packet = packet

            last_packet = packet

    return {
            "first_packet_timestamp":float(first_packet.time), 
            "second_packet_timestamp":float(last_packet.time)
            }
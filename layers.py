from scapy.all import Ether, IP, Packet, Raw, UDP

from bvlc import process_bvlc

# --- LAYER PROCESSORS ---

def process_ether_layer(ether_layer: Ether) -> dict[str, str]:
    """
    Extract the source and destination MAC addresses
    from an Ethernet layer.
    """

    source_mac = ether_layer.src
    destination_mac = ether_layer.dst

    # TODO: Implement manufacturer identification

    return {
        "source_mac": source_mac,
        "destination_mac": destination_mac,
    }


def process_ip_layer(ip_layer: IP) -> dict[str, str]:
    """
    Extract the source and destination IP addresses
    from an IP layer.
    """

    source_ip = ip_layer.src
    destination_ip = ip_layer.dst

    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
    }


def process_udp_layer(udp_layer: UDP) -> dict[str, int]:
    """
    Extract the source and destination ports
    from a UDP layer.
    """

    source_port = udp_layer.sport
    destination_port = udp_layer.dport

    return {
        "source_port": source_port,
        "destination_port": destination_port,
    }

def process_raw_layer(raw_layer: Raw) -> None:

    if raw_layer[0] in (0x81, 0x82):
        process_bvlc(raw_layer)

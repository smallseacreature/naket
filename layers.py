"""Extract link, network, transport, and BACnet payload fields from Scapy.

Each processor returns only the record for the layer it was given. The packet
orchestration code in ``main.py`` is responsible for placing those records
under the ``ethernet``, ``ip``, ``udp``, and ``bvlc`` keys expected by the
database insertion layer.
"""

from __future__ import annotations

from typing import Any

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from bvlc import process_bvlc
from constants import BVLC_TYPES


LayerRecord = dict[str, Any]


def _optional_int(value: Any) -> int | None:
    """Convert a Scapy numeric field to ``int`` while preserving ``None``."""
    if value is None:
        return None

    return int(value)


def process_ether_layer(ether_layer: Ether) -> LayerRecord:
    """Extract the Ethernet fields stored by the project database."""
    return {
        "source_mac": str(ether_layer.src),
        "destination_mac": str(ether_layer.dst),
        "ether_type": _optional_int(ether_layer.type),
    }


def process_ip_layer(ip_layer: IP) -> LayerRecord:
    """Extract IPv4 header fields from a Scapy ``IP`` layer.

    Scapy stores ``ihl`` as a count of 32-bit words. The database stores the
    more useful header length in bytes, so the value is multiplied by four.
    IP flags are converted from Scapy's ``FlagValue`` object to their numeric
    three-bit representation.
    """
    ihl_words = _optional_int(ip_layer.ihl)
    header_length = None if ihl_words is None else ihl_words * 4

    return {
        "ip_version": _optional_int(ip_layer.version),
        "source_ip": str(ip_layer.src),
        "destination_ip": str(ip_layer.dst),
        "protocol": _optional_int(ip_layer.proto),
        "ttl": _optional_int(ip_layer.ttl),
        "identification": _optional_int(ip_layer.id),
        "flags": _optional_int(ip_layer.flags),
        "fragment_offset": _optional_int(ip_layer.frag),
        "header_length": header_length,
        "total_length": _optional_int(ip_layer.len),
        "checksum": _optional_int(ip_layer.chksum),
    }


def process_udp_layer(udp_layer: UDP) -> LayerRecord:
    """Extract UDP header fields from a Scapy ``UDP`` layer."""
    return {
        "source_port": int(udp_layer.sport),
        "destination_port": int(udp_layer.dport),
        "udp_length": _optional_int(udp_layer.len),
        "checksum": _optional_int(udp_layer.chksum),
    }


def process_bacnet_payload(
    payload: bytes | bytearray | memoryview,
) -> LayerRecord | None:
    """Parse a byte payload when it begins with a recognized BVLC type.

    ``0x81`` identifies BACnet/IP over IPv4 and ``0x82`` identifies
    BACnet/IP over IPv6. A payload that does not begin with a known BVLC type
    is not treated as BACnet merely because it was transported over UDP.
    """
    data = bytes(payload)

    if not data or data[0] not in BVLC_TYPES:
        return None

    return process_bvlc(data)


def process_udp_payload(udp_layer: UDP) -> LayerRecord | None:
    """Parse the complete UDP payload as a possible BVLC message.

    Reading ``udp_layer.payload`` is more reliable than requiring a Scapy
    ``Raw`` layer because Scapy or an installed dissector may decode the UDP
    payload into another packet class.
    """
    payload = bytes(udp_layer.payload)

    if not payload:
        return None

    return process_bacnet_payload(payload)


def process_raw_layer(raw_layer: Raw) -> LayerRecord | None:
    """Compatibility wrapper for parsing a Scapy ``Raw`` payload.

    New packet-processing code should prefer :func:`process_udp_payload` so it
    always receives the complete UDP payload.
    """
    return process_bacnet_payload(bytes(raw_layer.load))
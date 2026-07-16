"""Parse BACnet Network Protocol Data Units (NPDUs).

The NPDU parser extracts BACnet routing information and then dispatches the
remaining payload either to the APDU parser or preserves it as a network-layer
message. Network-message body decoding can be added later without changing the
record format produced here.
"""

from __future__ import annotations

from typing import Any

from apdu import process_apdu
from constants import (
    BACNET_PROTOCOL_VERSION,
    NPDU_NETWORK_MESSAGES,
    NPDU_PRIORITIES,
    NPDU_PROPRIETARY_MESSAGE_MIN,
)


NPDURecord = dict[str, Any]

# Bits 6 and 4 of the NPDU control octet are reserved and must be zero.
_RESERVED_CONTROL_MASK = 0x50


def _format_address(address: bytes | None) -> str | None:
    """Return a readable, non-lossy representation of a BACnet MAC address."""
    if address is None:
        return None

    if len(address) == 0:
        return "Broadcast"

    return ":".join(f"{octet:02X}" for octet in address)


def _network_message_name(message_type: int) -> str:
    """Resolve standard, reserved, and vendor-proprietary message types."""
    standard_name = NPDU_NETWORK_MESSAGES.get(message_type)
    if standard_name is not None:
        return standard_name

    if message_type >= NPDU_PROPRIETARY_MESSAGE_MIN:
        return "Vendor Proprietary Message"

    return "Reserved Network Message Type"


def process_npdu(data: bytes) -> NPDURecord | None:
    """Parse one BACnet NPDU.

    Args:
        data: Bytes beginning with the BACnet protocol version octet.

    Returns:
        A dictionary containing the NPCI fields, raw NPDU payload, and either a
        parsed ``apdu`` or network-message metadata. ``None`` is returned when
        the NPDU header is truncated or violates required header rules.

        A malformed APDU does not erase an otherwise valid NPDU header. In that
        case, ``apdu`` is ``None`` and ``apdu_parse_valid`` is ``False`` while
        ``raw_payload`` still preserves the APDU bytes.
    """
    # Every NPDU begins with a version octet and a control octet.
    if len(data) < 2:
        return None

    npdu_version = data[0]
    control_byte = data[1]

    if npdu_version != BACNET_PROTOCOL_VERSION:
        return None

    # Reserved control bits must be zero.
    if control_byte & _RESERVED_CONTROL_MASK:
        return None

    network_layer_message = bool(control_byte & 0x80)
    destination_present = bool(control_byte & 0x20)
    source_present = bool(control_byte & 0x08)
    expecting_reply = bool(control_byte & 0x04)
    priority_code = control_byte & 0x03

    offset = 2

    destination_network: int | None = None
    destination_address_length: int | None = None
    destination_address: bytes | None = None
    destination_is_broadcast = False
    destination_is_global_broadcast = False

    source_network: int | None = None
    source_address_length: int | None = None
    source_address: bytes | None = None

    hop_count: int | None = None

    # ------------------------------------------------------------------
    # Destination routing information: DNET, DLEN, DADR
    # ------------------------------------------------------------------
    if destination_present:
        # DNET is two octets and DLEN is one octet.
        if len(data) < offset + 3:
            return None

        destination_network = int.from_bytes(
            data[offset : offset + 2],
            "big",
        )
        offset += 2

        destination_address_length = data[offset]
        offset += 1

        if len(data) < offset + destination_address_length:
            return None

        # An empty DADR is meaningful: it identifies a broadcast on DNET.
        destination_address = data[
            offset : offset + destination_address_length
        ]
        offset += destination_address_length

        destination_is_broadcast = destination_address_length == 0
        destination_is_global_broadcast = (
            destination_is_broadcast
            and destination_network == 0xFFFF
        )

    # ------------------------------------------------------------------
    # Source routing information: SNET, SLEN, SADR
    # ------------------------------------------------------------------
    if source_present:
        # SNET is two octets and SLEN is one octet.
        if len(data) < offset + 3:
            return None

        source_network = int.from_bytes(
            data[offset : offset + 2],
            "big",
        )
        offset += 2

        source_address_length = data[offset]
        offset += 1

        # Unlike DLEN, an SLEN of zero is invalid because a source address
        # cannot represent a broadcast.
        if source_address_length == 0:
            return None

        if len(data) < offset + source_address_length:
            return None

        source_address = data[offset : offset + source_address_length]
        offset += source_address_length

    # Hop Count is present whenever destination routing information exists.
    if destination_present:
        if len(data) < offset + 1:
            return None

        hop_count = data[offset]
        offset += 1

    # The NSDU must contain either a network-layer message or an APDU.
    if len(data) <= offset:
        return None

    header_length = offset
    raw_payload = data[offset:]

    network_message_type: int | None = None
    network_message_name: str | None = None
    vendor_id: int | None = None
    network_message_data: bytes | None = None
    apdu_result: dict[str, Any] | None = None
    apdu_parse_valid: bool | None = None

    # ------------------------------------------------------------------
    # Network-layer message
    # ------------------------------------------------------------------
    if network_layer_message:
        network_message_type = raw_payload[0]
        network_message_name = _network_message_name(network_message_type)
        message_offset = 1

        # Vendor-proprietary network messages include a two-octet Vendor ID
        # immediately after the Message Type octet.
        if network_message_type >= NPDU_PROPRIETARY_MESSAGE_MIN:
            if len(raw_payload) < message_offset + 2:
                return None

            vendor_id = int.from_bytes(
                raw_payload[message_offset : message_offset + 2],
                "big",
            )
            message_offset += 2

        network_message_data = raw_payload[message_offset:]

    # ------------------------------------------------------------------
    # Application-layer message
    # ------------------------------------------------------------------
    else:
        apdu_result = process_apdu(raw_payload)
        apdu_parse_valid = apdu_result is not None

    return {
        "npdu_version": npdu_version,
        "control_byte": control_byte,
        "network_layer_message": network_layer_message,
        "destination_present": destination_present,
        "source_present": source_present,
        "expecting_reply": expecting_reply,
        "priority_code": priority_code,
        "priority_name": NPDU_PRIORITIES[priority_code],
        "destination_network": destination_network,
        "destination_address_length": destination_address_length,
        "destination_address": destination_address,
        "destination_address_text": _format_address(
            destination_address
        ),
        "destination_is_broadcast": destination_is_broadcast,
        "destination_is_global_broadcast": (
            destination_is_global_broadcast
        ),
        "source_network": source_network,
        "source_address_length": source_address_length,
        "source_address": source_address,
        "source_address_text": _format_address(source_address),
        "hop_count": hop_count,
        "header_length": header_length,
        "payload_length": len(raw_payload),
        "network_message_type": network_message_type,
        "network_message_name": network_message_name,
        "vendor_id": vendor_id,
        "network_message_data": network_message_data,
        "apdu": apdu_result,
        "apdu_parse_valid": apdu_parse_valid,
        "raw_payload": raw_payload,
    }
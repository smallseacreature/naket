"""Parse BACnet Virtual Link Control (BVLC) messages.

This module fully parses the BACnet/IP over IPv4 BVLC header and the standard
IPv4 BVLC function bodies used by this project. BACnet/IPv6 headers are
recognized and preserved, but their function bodies are intentionally left
opaque until IPv6 layer support is added to the rest of the packet pipeline.
"""

from __future__ import annotations

from ipaddress import IPv4Address
from typing import Any, Callable

from constants import (
    BVLC_TYPES,
    get_bvlc_function_name,
    get_bvlc_result_name,
)
from npdu import process_npdu


BVLCRecord = dict[str, Any]
BodyProcessor = Callable[[bytes], BVLCRecord]

BVLC_IPV4_TYPE = 0x81
BVLC_IPV6_TYPE = 0x82
BVLC_HEADER_LENGTH = 4
BIP_ADDRESS_LENGTH = 6
BDT_ENTRY_LENGTH = 10
FDT_ENTRY_LENGTH = 10
SECURITY_SIGNATURE_LENGTH = 16


def _valid_body(**fields: Any) -> BVLCRecord:
    """Return fields for a successfully parsed BVLC body."""
    return {
        "body_parse_valid": True,
        "body_parse_error": None,
        **fields,
    }


def _invalid_body(message: str, **fields: Any) -> BVLCRecord:
    """Return any recoverable fields from an invalid BVLC body."""
    return {
        "body_parse_valid": False,
        "body_parse_error": message,
        **fields,
    }


def process_result(data: bytes) -> BVLCRecord:
    """Parse a two-octet BVLC-Result body."""
    if len(data) != 2:
        return _invalid_body(
            "BVLC-Result body must be exactly 2 bytes",
        )

    return _valid_body(
        result_code=int.from_bytes(data, "big"),
    )


def process_bdt(data: bytes) -> BVLCRecord:
    """Parse zero or more ten-octet Broadcast Distribution Table entries."""
    if len(data) % BDT_ENTRY_LENGTH != 0:
        return _invalid_body(
            "BDT body length must be a multiple of 10 bytes",
        )

    entries: list[dict[str, Any]] = []

    for entry_number, offset in enumerate(
        range(0, len(data), BDT_ENTRY_LENGTH)
    ):
        entry = data[offset : offset + BDT_ENTRY_LENGTH]

        entries.append(
            {
                "entry_number": entry_number,
                "ip_address": str(IPv4Address(entry[0:4])),
                "udp_port": int.from_bytes(entry[4:6], "big"),
                "broadcast_mask": str(IPv4Address(entry[6:10])),
            }
        )

    return _valid_body(bdt_entries=entries)


def process_no_body(data: bytes) -> BVLCRecord:
    """Validate a BVLC function whose body must be empty."""
    if data:
        return _invalid_body(
            "This BVLC function must not contain a body",
        )

    return _valid_body()


def process_forwarded_npdu(data: bytes) -> BVLCRecord:
    """Parse an originating B/IP address followed by an NPDU."""
    if len(data) < BIP_ADDRESS_LENGTH:
        return _invalid_body(
            "Forwarded-NPDU body is missing the 6-byte originating address",
        )

    originating_ip = str(IPv4Address(data[0:4]))
    originating_port = int.from_bytes(data[4:6], "big")
    npdu_bytes = data[BIP_ADDRESS_LENGTH:]

    if not npdu_bytes:
        return _invalid_body(
            "Forwarded-NPDU body does not contain an NPDU",
            originating_ip=originating_ip,
            originating_port=originating_port,
            npdu=None,
            npdu_parse_valid=False,
        )

    npdu_result = process_npdu(npdu_bytes)

    if npdu_result is None:
        return _invalid_body(
            "Forwarded-NPDU contains a malformed or unsupported NPDU",
            originating_ip=originating_ip,
            originating_port=originating_port,
            npdu=None,
            npdu_parse_valid=False,
        )

    return _valid_body(
        originating_ip=originating_ip,
        originating_port=originating_port,
        npdu=npdu_result,
        npdu_parse_valid=True,
    )


def process_foreign_device_registration(data: bytes) -> BVLCRecord:
    """Parse the two-octet TTL in a Register-Foreign-Device message."""
    if len(data) != 2:
        return _invalid_body(
            "Register-Foreign-Device body must be exactly 2 bytes",
        )

    return _valid_body(
        registration_ttl=int.from_bytes(data, "big"),
    )


def process_fdt(data: bytes) -> BVLCRecord:
    """Parse zero or more ten-octet Foreign Device Table entries."""
    if len(data) % FDT_ENTRY_LENGTH != 0:
        return _invalid_body(
            "FDT body length must be a multiple of 10 bytes",
        )

    entries: list[dict[str, Any]] = []

    for entry_number, offset in enumerate(
        range(0, len(data), FDT_ENTRY_LENGTH)
    ):
        entry = data[offset : offset + FDT_ENTRY_LENGTH]

        entries.append(
            {
                "entry_number": entry_number,
                "ip_address": str(IPv4Address(entry[0:4])),
                "udp_port": int.from_bytes(entry[4:6], "big"),
                "ttl": int.from_bytes(entry[6:8], "big"),
                "remaining_time": int.from_bytes(entry[8:10], "big"),
            }
        )

    return _valid_body(fdt_entries=entries)


def process_delete_fdt_entry(data: bytes) -> BVLCRecord:
    """Parse the six-octet B/IP address of an FDT entry to delete."""
    if len(data) != BIP_ADDRESS_LENGTH:
        return _invalid_body(
            "Delete-Foreign-Device-Table-Entry body must be exactly 6 bytes",
        )

    return _valid_body(
        delete_ip=str(IPv4Address(data[0:4])),
        delete_port=int.from_bytes(data[4:6], "big"),
    )


def process_npdu_body(data: bytes) -> BVLCRecord:
    """Parse a BVLC body that consists entirely of one NPDU."""
    if not data:
        return _invalid_body(
            "BVLC function requires an NPDU body",
            npdu=None,
            npdu_parse_valid=False,
        )

    npdu_result = process_npdu(data)

    if npdu_result is None:
        return _invalid_body(
            "BVLC function contains a malformed or unsupported NPDU",
            npdu=None,
            npdu_parse_valid=False,
        )

    return _valid_body(
        npdu=npdu_result,
        npdu_parse_valid=True,
    )


def process_secure_bvll(data: bytes) -> BVLCRecord:
    """Preserve the major boundaries of a Secure-BVLL Security Wrapper.

    The BACnet Security Wrapper is variable-length and can contain encrypted
    fields. This parser therefore does not pretend to decode the complete
    wrapper. It safely preserves the control octet, wrapper data, and required
    final 16-octet signature for future security-layer processing.
    """
    minimum_length = 1 + SECURITY_SIGNATURE_LENGTH

    if len(data) < minimum_length:
        return _invalid_body(
            "Secure-BVLL body is too short to contain control and signature",
        )

    return {
        "body_parse_valid": None,
        "body_parse_error": None,
        "security_control": data[0],
        "security_wrapper_data": data[1:-SECURITY_SIGNATURE_LENGTH],
        "security_signature": data[-SECURITY_SIGNATURE_LENGTH:],
        "unsupported_reason": (
            "Complete BACnet Security Wrapper decoding is not implemented"
        ),
    }


# The dispatcher is keyed by both BVLC type and function code. Function codes
# are not globally unique between BACnet/IPv4 and BACnet/IPv6.
BVLC_PROCESSORS: dict[tuple[int, int], BodyProcessor] = {
    (BVLC_IPV4_TYPE, 0x00): process_result,
    (BVLC_IPV4_TYPE, 0x01): process_bdt,
    (BVLC_IPV4_TYPE, 0x02): process_no_body,
    (BVLC_IPV4_TYPE, 0x03): process_bdt,
    (BVLC_IPV4_TYPE, 0x04): process_forwarded_npdu,
    (BVLC_IPV4_TYPE, 0x05): process_foreign_device_registration,
    (BVLC_IPV4_TYPE, 0x06): process_no_body,
    (BVLC_IPV4_TYPE, 0x07): process_fdt,
    (BVLC_IPV4_TYPE, 0x08): process_delete_fdt_entry,
    (BVLC_IPV4_TYPE, 0x09): process_npdu_body,
    (BVLC_IPV4_TYPE, 0x0A): process_npdu_body,
    (BVLC_IPV4_TYPE, 0x0B): process_npdu_body,
    (BVLC_IPV4_TYPE, 0x0C): process_secure_bvll,
}


def process_bvlc(data: bytes) -> BVLCRecord | None:
    """Parse one BACnet Virtual Link Control message.

    A complete four-octet BVLC header is required. Once that header exists, the
    function returns a record even when the declared length or function body is
    malformed, allowing the caller to retain useful forensic information.
    """
    if len(data) < BVLC_HEADER_LENGTH:
        return None

    type_code = data[0]
    function_code = data[1]
    declared_length = int.from_bytes(data[2:4], "big")
    actual_length = len(data)

    type_name = BVLC_TYPES.get(type_code, "Unknown BVLC Type")
    function_name = get_bvlc_function_name(type_code, function_code)

    declared_length_valid = declared_length >= BVLC_HEADER_LENGTH
    complete_declared_message = declared_length <= actual_length
    length_valid = declared_length == actual_length and declared_length_valid

    if declared_length_valid and complete_declared_message:
        raw_body = data[BVLC_HEADER_LENGTH:declared_length]
        trailing_data = data[declared_length:]
    else:
        # Preserve every received byte after the header when the declared
        # message is impossible or truncated.
        raw_body = data[BVLC_HEADER_LENGTH:]
        trailing_data = b""

    result: BVLCRecord = {
        "bvlc_type_code": type_code,
        "bvlc_type_name": type_name,
        "function_code": function_code,
        "function_name": function_name,
        "declared_length": declared_length,
        "actual_length": actual_length,
        "length_valid": length_valid,
        "body_parse_valid": None,
        "body_parse_error": None,
        "parse_valid": False,
        "result_code": None,
        "result_name": None,
        "originating_ip": None,
        "originating_port": None,
        "registration_ttl": None,
        "delete_ip": None,
        "delete_port": None,
        "bdt_entries": [],
        "fdt_entries": [],
        "npdu": None,
        "npdu_parse_valid": None,
        "security_control": None,
        "security_wrapper_data": None,
        "security_signature": None,
        "raw_body": raw_body,
        "trailing_data": trailing_data,
        "unsupported_reason": None,
    }

    if not declared_length_valid:
        result.update(
            {
                "body_parse_valid": False,
                "body_parse_error": (
                    "Declared BVLC length cannot be smaller than 4 bytes"
                ),
            }
        )
        return result

    if not complete_declared_message:
        result.update(
            {
                "body_parse_valid": False,
                "body_parse_error": (
                    "BVLC message is truncated before its declared length"
                ),
            }
        )
        return result

    processor = BVLC_PROCESSORS.get((type_code, function_code))

    if processor is None:
        if type_code == BVLC_IPV6_TYPE:
            unsupported_reason = (
                "BACnet/IPv6 BVLC body parsing is not implemented"
            )
        elif type_code not in BVLC_TYPES:
            unsupported_reason = "Unknown BVLC type"
        else:
            unsupported_reason = "Unknown or unsupported BVLC function"

        result["unsupported_reason"] = unsupported_reason
        return result

    body_result = processor(raw_body)
    result.update(body_result)

    result_code = result.get("result_code")
    if result_code is not None:
        result["result_name"] = get_bvlc_result_name(
            type_code,
            result_code,
        )

    result["parse_valid"] = bool(
        result["length_valid"] and result["body_parse_valid"]
    )

    return result

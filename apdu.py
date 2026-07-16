"""Parse BACnet Application Protocol Data Units (APDUs).

This module parses the common APDU header fields and preserves the remaining
service payload as raw bytes. Decoding individual BACnet service payloads is a
separate responsibility and can be added later without changing this header
parser's output format.
"""

from __future__ import annotations

from typing import Any

from constants import (
    APDU_MAX_LENGTH_ACCEPTED,
    APDU_MAX_SEGMENTS_ACCEPTED,
    APDU_TYPES,
    CONFIRMED_SERVICES,
    UNCONFIRMED_SERVICES,
)


APDURecord = dict[str, Any]


def _base_result(first_byte: int) -> APDURecord:
    """Create a consistent result shape for every APDU type."""
    pdu_type_code = (first_byte >> 4) & 0x0F

    return {
        "first_byte": first_byte,
        "pdu_type_code": pdu_type_code,
        "pdu_type_name": APDU_TYPES.get(
            pdu_type_code,
            "Unknown APDU Type",
        ),
        "flags": first_byte & 0x0F,
        "segmented_message": None,
        "more_follows": None,
        "segmented_response_accepted": None,
        "negative_ack": None,
        "server": None,
        "max_segments_code": None,
        "max_segments_accepted": None,
        "max_apdu_code": None,
        "max_apdu_length": None,
        "invoke_id": None,
        "sequence_number": None,
        "proposed_window_size": None,
        "actual_window_size": None,
        "service_family": None,
        "service_choice": None,
        "service_name": None,
        "error_class": None,
        "error_code": None,
        "reject_reason": None,
        "abort_reason": None,
        "raw_service_data": None,
    }


def _service_name(service_family: str, service_choice: int) -> str:
    """Resolve a confirmed or unconfirmed BACnet service name."""
    if service_family == "confirmed":
        return CONFIRMED_SERVICES.get(
            service_choice,
            "Unknown Confirmed Service",
        )

    return UNCONFIRMED_SERVICES.get(
        service_choice,
        "Unknown Unconfirmed Service",
    )


def _decode_application_enumerated(
    data: bytes,
    offset: int,
) -> tuple[int | None, int]:
    """Decode one simple BACnet application-tagged Enumerated value.

    This helper intentionally handles only the normal one- through four-byte
    form. It is used as a best-effort decoder for the common Error APDU layout.
    If the next value is not an application-tagged Enumerated value, the caller
    receives ``None`` and the original offset.
    """
    if offset >= len(data):
        return None, offset

    tag_header = data[offset]
    tag_number = (tag_header >> 4) & 0x0F
    is_context_specific = bool(tag_header & 0x08)
    value_length = tag_header & 0x07

    if tag_number != 0x09 or is_context_specific:
        return None, offset

    if value_length not in (1, 2, 3, 4):
        return None, offset

    value_start = offset + 1
    value_end = value_start + value_length

    if value_end > len(data):
        return None, offset

    value = int.from_bytes(data[value_start:value_end], "big")
    return value, value_end


def process_apdu(data: bytes) -> APDURecord | None:
    """Parse one BACnet APDU.

    Args:
        data: Bytes beginning with the APDU's first header byte.

    Returns:
        A dictionary containing a consistent set of APDU header fields, or
        ``None`` when the bytes are truncated or violate the APDU header rules.

        Reserved/unknown APDU type codes are preserved as an unsupported record
        rather than discarded, because their raw payload may still be useful
        during packet analysis.
    """
    if not data:
        return None

    first_byte = data[0]
    pdu_type_code = (first_byte >> 4) & 0x0F
    flags = first_byte & 0x0F
    result = _base_result(first_byte)

    # ------------------------------------------------------------------
    # 0x00: Confirmed-Request-PDU
    # ------------------------------------------------------------------
    if pdu_type_code == 0x00:
        segmented_message = bool(first_byte & 0x08)
        more_follows = bool(first_byte & 0x04)
        segmented_response_accepted = bool(first_byte & 0x02)
        reserved = bool(first_byte & 0x01)

        if reserved or (more_follows and not segmented_message):
            return None

        # First byte, max-segments/max-APDU byte, and invoke ID.
        if len(data) < 3:
            return None

        max_information = data[1]

        # Bit 7 is reserved in this byte and must be zero.
        if max_information & 0x80:
            return None

        max_segments_code = (max_information >> 4) & 0x07
        max_apdu_code = max_information & 0x0F
        max_apdu_length = APDU_MAX_LENGTH_ACCEPTED.get(max_apdu_code)

        # Codes 0 through 5 are currently defined. Preserve neither a guessed
        # size nor a malformed header when a reserved code is encountered.
        if max_apdu_length is None:
            return None

        invoke_id = data[2]
        offset = 3
        sequence_number = None
        proposed_window_size = None

        if segmented_message:
            if len(data) < offset + 2:
                return None

            sequence_number = data[offset]
            proposed_window_size = data[offset + 1]
            offset += 2

        if len(data) < offset + 1:
            return None

        service_choice = data[offset]
        raw_service_data = data[offset + 1 :]

        result.update(
            {
                "segmented_message": segmented_message,
                "more_follows": more_follows,
                "segmented_response_accepted": (
                    segmented_response_accepted
                ),
                "max_segments_code": max_segments_code,
                "max_segments_accepted": APDU_MAX_SEGMENTS_ACCEPTED[
                    max_segments_code
                ],
                "max_apdu_code": max_apdu_code,
                "max_apdu_length": max_apdu_length,
                "invoke_id": invoke_id,
                "sequence_number": sequence_number,
                "proposed_window_size": proposed_window_size,
                "service_family": "confirmed",
                "service_choice": service_choice,
                "service_name": _service_name(
                    "confirmed",
                    service_choice,
                ),
                "raw_service_data": raw_service_data,
            }
        )
        return result

    # ------------------------------------------------------------------
    # 0x01: Unconfirmed-Request-PDU
    # ------------------------------------------------------------------
    if pdu_type_code == 0x01:
        if flags != 0 or len(data) < 2:
            return None

        service_choice = data[1]

        result.update(
            {
                "service_family": "unconfirmed",
                "service_choice": service_choice,
                "service_name": _service_name(
                    "unconfirmed",
                    service_choice,
                ),
                "raw_service_data": data[2:],
            }
        )
        return result

    # ------------------------------------------------------------------
    # 0x02: SimpleACK-PDU
    # ------------------------------------------------------------------
    if pdu_type_code == 0x02:
        if flags != 0 or len(data) != 3:
            return None

        service_choice = data[2]

        result.update(
            {
                "invoke_id": data[1],
                "service_family": "confirmed",
                "service_choice": service_choice,
                "service_name": _service_name(
                    "confirmed",
                    service_choice,
                ),
                "raw_service_data": b"",
            }
        )
        return result

    # ------------------------------------------------------------------
    # 0x03: ComplexACK-PDU
    # ------------------------------------------------------------------
    if pdu_type_code == 0x03:
        segmented_message = bool(first_byte & 0x08)
        more_follows = bool(first_byte & 0x04)
        reserved_flags = flags & 0x03

        if reserved_flags != 0 or (
            more_follows and not segmented_message
        ):
            return None

        if len(data) < 2:
            return None

        invoke_id = data[1]
        offset = 2
        sequence_number = None
        proposed_window_size = None

        if segmented_message:
            if len(data) < offset + 2:
                return None

            sequence_number = data[offset]
            proposed_window_size = data[offset + 1]
            offset += 2

        if len(data) < offset + 1:
            return None

        service_choice = data[offset]

        result.update(
            {
                "segmented_message": segmented_message,
                "more_follows": more_follows,
                "invoke_id": invoke_id,
                "sequence_number": sequence_number,
                "proposed_window_size": proposed_window_size,
                "service_family": "confirmed",
                "service_choice": service_choice,
                "service_name": _service_name(
                    "confirmed",
                    service_choice,
                ),
                "raw_service_data": data[offset + 1 :],
            }
        )
        return result

    # ------------------------------------------------------------------
    # 0x04: SegmentACK-PDU
    # ------------------------------------------------------------------
    if pdu_type_code == 0x04:
        negative_ack = bool(first_byte & 0x02)
        server = bool(first_byte & 0x01)
        reserved_flags = flags & 0x0C

        if reserved_flags != 0 or len(data) != 4:
            return None

        result.update(
            {
                "negative_ack": negative_ack,
                "server": server,
                "invoke_id": data[1],
                "sequence_number": data[2],
                "actual_window_size": data[3],
            }
        )
        return result

    # ------------------------------------------------------------------
    # 0x05: Error-PDU
    # ------------------------------------------------------------------
    if pdu_type_code == 0x05:
        if flags != 0 or len(data) < 3:
            return None

        service_choice = data[2]
        raw_service_data = data[3:]

        # Most Error PDUs begin with application-tagged Enumerated values for
        # error-class and error-code. Some services define a different error
        # structure, so failure to decode these two values is not fatal.
        error_class, next_offset = _decode_application_enumerated(
            raw_service_data,
            0,
        )
        error_code = None

        if error_class is not None:
            error_code, _ = _decode_application_enumerated(
                raw_service_data,
                next_offset,
            )

            if error_code is None:
                error_class = None

        result.update(
            {
                "invoke_id": data[1],
                "service_family": "confirmed",
                "service_choice": service_choice,
                "service_name": _service_name(
                    "confirmed",
                    service_choice,
                ),
                "error_class": error_class,
                "error_code": error_code,
                "raw_service_data": raw_service_data,
            }
        )
        return result

    # ------------------------------------------------------------------
    # 0x06: Reject-PDU
    # ------------------------------------------------------------------
    if pdu_type_code == 0x06:
        if flags != 0 or len(data) != 3:
            return None

        result.update(
            {
                "invoke_id": data[1],
                "reject_reason": data[2],
            }
        )
        return result

    # ------------------------------------------------------------------
    # 0x07: Abort-PDU
    # ------------------------------------------------------------------
    if pdu_type_code == 0x07:
        server = bool(first_byte & 0x01)
        reserved_flags = flags & 0x0E

        if reserved_flags != 0 or len(data) != 3:
            return None

        result.update(
            {
                "server": server,
                "invoke_id": data[1],
                "abort_reason": data[2],
            }
        )
        return result

    # Types 0x08 through 0x0F are not standard APDU types. Preserve their
    # raw bytes so unsupported traffic remains visible to the pipeline.
    result["raw_service_data"] = data[1:]
    return result
from constants import APDU_TYPES

def process_apdu(data: bytes) -> dict | None:

    # Every APDU must contain at least the first header byte
    if len(data) < 1:
        return None

    first_byte = data[0]

    # Upper four bits identify the APDU type
    pdu_type_code = (first_byte >> 4) & 0x0F
    pdu_type_name = APDU_TYPES.get(
        pdu_type_code,
        "Unknown APDU Type"
    )

    # Lower four bits contain flags whose meanings depend
    # on the APDU type
    flags = first_byte & 0x0F

    result = {
        "pdu_type_code": pdu_type_code,
        "pdu_type_name": pdu_type_name,
        "flags": flags,
    }

    # --- 0x00: CONFIRMED REQUEST ---

    if pdu_type_code == 0x00:

        # Minimum unsegmented structure:
        # Byte 0: Type and flags
        # Byte 1: Maximum segments / maximum APDU size
        # Byte 2: Invoke ID
        # Byte 3: Service choice
        if len(data) < 4:
            return None

        segmented_message = bool(first_byte & 0x08)
        more_follows = bool(first_byte & 0x04)
        segmented_response_accepted = bool(first_byte & 0x02)
        reserved = bool(first_byte & 0x01)

        if reserved:
            return None

        if more_follows and not segmented_message:
            return None

        offset = 1

        max_information = data[offset]
        offset += 1

        if max_information & 0x80:
            return None

        # These are encoded enumeration values, not literal sizes
        max_segments_accepted_code = (
            max_information >> 4
        ) & 0x07

        max_apdu_size_accepted_code = (
            max_information & 0x0F
        )

        invoke_id = data[offset]
        offset += 1

        sequence_number = None
        proposed_window_size = None

        if segmented_message:

            if len(data) < offset + 2:
                return None

            sequence_number = data[offset]
            offset += 1

            proposed_window_size = data[offset]
            offset += 1

        if len(data) < offset + 1:
            return None

        service_choice = data[offset]
        offset += 1

        service_data = data[offset:]

        result.update({
            "segmented_message": segmented_message,
            "more_follows": more_follows,
            "segmented_response_accepted": (
                segmented_response_accepted
            ),
            "reserved": reserved,
            "max_segments_accepted_code": (
                max_segments_accepted_code
            ),
            "max_apdu_size_accepted_code": (
                max_apdu_size_accepted_code
            ),
            "invoke_id": invoke_id,
            "sequence_number": sequence_number,
            "proposed_window_size": proposed_window_size,
            "service_choice": service_choice,
            "service_data": service_data,
        })

        return result

    # --- 0x01: UNCONFIRMED REQUEST ---

    if pdu_type_code == 0x01:

        # Structure:
        # Byte 0: Type
        # Byte 1: Service choice
        # Remaining bytes: Service data
        if len(data) < 2:
            return None

        if flags != 0:
            return None

        service_choice = data[1]
        service_data = data[2:]

        result.update({
            "reserved_flags": flags,
            "service_choice": service_choice,
            "service_data": service_data,
        })

        return result

    # --- 0x02: SIMPLE ACK ---

    if pdu_type_code == 0x02:

        # Structure:
        # Byte 0: Type
        # Byte 1: Invoke ID
        # Byte 2: Service choice
        if len(data) != 3:
            return None

        if flags != 0:
            return None

        invoke_id = data[1]
        service_choice = data[2]

        result.update({
            "reserved_flags": flags,
            "invoke_id": invoke_id,
            "service_choice": service_choice,
        })

        return result

    # --- 0x03: COMPLEX ACK ---

    if pdu_type_code == 0x03:

        # Minimum unsegmented structure:
        # Byte 0: Type and flags
        # Byte 1: Invoke ID
        # Byte 2: Service choice
        if len(data) < 3:
            return None

        segmented_message = bool(first_byte & 0x08)
        more_follows = bool(first_byte & 0x04)
        reserved_flags = flags & 0x03

        if reserved_flags != 0:
            return None

        if more_follows and not segmented_message:
            return None

        offset = 1

        invoke_id = data[offset]
        offset += 1

        sequence_number = None
        proposed_window_size = None

        if segmented_message:

            if len(data) < offset + 2:
                return None

            sequence_number = data[offset]
            offset += 1

            proposed_window_size = data[offset]
            offset += 1

        if len(data) < offset + 1:
            return None

        service_choice = data[offset]
        offset += 1

        service_ack_data = data[offset:]

        result.update({
            "segmented_message": segmented_message,
            "more_follows": more_follows,
            "reserved_flags": reserved_flags,
            "invoke_id": invoke_id,
            "sequence_number": sequence_number,
            "proposed_window_size": proposed_window_size,
            "service_choice": service_choice,
            "service_ack_data": service_ack_data,
        })

        return result

    # --- 0x04: SEGMENT ACK ---

    if pdu_type_code == 0x04:

        # Structure:
        # Byte 0: Type and flags
        # Byte 1: Invoke ID
        # Byte 2: Sequence number
        # Byte 3: Actual window size
        if len(data) != 4:
            return None

        negative_ack = bool(first_byte & 0x02)
        server = bool(first_byte & 0x01)
        reserved_flags = flags & 0x0C

        if reserved_flags != 0:
            return None

        invoke_id = data[1]
        sequence_number = data[2]
        actual_window_size = data[3]

        result.update({
            "negative_ack": negative_ack,
            "server": server,
            "reserved_flags": reserved_flags,
            "invoke_id": invoke_id,
            "sequence_number": sequence_number,
            "actual_window_size": actual_window_size,
        })

        return result

    # --- 0x05: ERROR ---

    if pdu_type_code == 0x05:

        # Structure:
        # Byte 0: Type
        # Byte 1: Invoke ID
        # Byte 2: Service choice
        # Remaining bytes: Error data
        if len(data) < 3:
            return None

        if flags != 0:
            return None

        invoke_id = data[1]
        service_choice = data[2]
        error_data = data[3:]

        result.update({
            "reserved_flags": flags,
            "invoke_id": invoke_id,
            "service_choice": service_choice,
            "error_data": error_data,
        })

        return result

    # --- 0x06: REJECT ---

    if pdu_type_code == 0x06:

        # Structure:
        # Byte 0: Type
        # Byte 1: Invoke ID
        # Byte 2: Reject reason
        if len(data) != 3:
            return None

        if flags != 0:
            return None

        invoke_id = data[1]
        reject_reason = data[2]

        result.update({
            "reserved_flags": flags,
            "invoke_id": invoke_id,
            "reject_reason": reject_reason,
        })

        return result

    # --- 0x07: ABORT ---

    if pdu_type_code == 0x07:

        # Structure:
        # Byte 0: Type and server flag
        # Byte 1: Invoke ID
        # Byte 2: Abort reason
        if len(data) != 3:
            return None

        server = bool(first_byte & 0x01)
        reserved_flags = flags & 0x0E

        if reserved_flags != 0:
            return None

        invoke_id = data[1]
        abort_reason = data[2]

        result.update({
            "server": server,
            "reserved_flags": reserved_flags,
            "invoke_id": invoke_id,
            "abort_reason": abort_reason,
        })

        return result

    # Unknown or unsupported APDU type
    result.update({
        "unparsed_data": data[1:],
    })

    return result
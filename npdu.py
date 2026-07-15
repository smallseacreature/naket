from apdu import process_apdu

def process_npdu(data: bytes) -> dict | None:

    # An NPDU must contain at least a version and control byte
    if len(data) < 2:
        return None

    npdu_version = data[0]
    control = data[1]

    if npdu_version != 0x01:
        return None

    if control & 0x50:
        return None

    # Extract control flags with bit masks
    network_layer_message = bool(control & 0x80) #when true, the bytes after the NPDU do not contain an APDU
    destination_present = bool(control & 0x20)   #refers to internetwork destination, when the packet must travel through more BACnet routers
    source_present = bool(control & 0x08)        #true when the NPDU has been forwarded by a BACnet router from another BACnet network
    expecting_reply = bool(control & 0x04)
    priority = control & 0x03                    #BACnet uses these categories so time-sensitive things wont be delayed behind ordinary traffic.

    # Cursor pointing to the next unread byte
    offset = 2

    # These fields are optional within the NPDU
    destination_network = None
    destination_length = None
    destination_address = None

    source_network = None
    source_length = None
    source_address = None

    # this is like ttl, when it hits 0 the packet is killed
    hop_count = None

    # --- DESTINATION INFORMATION ---

    if destination_present:

        # We need at least:
        # DNET: 2 bytes
        # DLEN: 1 byte
        if len(data) < offset + 3:
            return None

        # DNET: Destination Network Number
        destination_network = int.from_bytes(
            data[offset:offset + 2],
            "big"
        )
        offset += 2

        # DLEN: Destination Address Length
        destination_length = data[offset]
        offset += 1

        # Make sure the complete destination address exists
        if len(data) < offset + destination_length:
            return None

        # DADR: Destination Address
        destination_address = data[
            offset:offset + destination_length
        ]
        offset += destination_length

    # --- SOURCE INFORMATION ---

    if source_present:

        # We need at least:
        # SNET: 2 bytes
        # SLEN: 1 byte
        if len(data) < offset + 3:
            return None

        # SNET: Source Network Number
        source_network = int.from_bytes(
            data[offset:offset + 2],
            "big"
        )
        offset += 2

        # SLEN: Source Address Length
        source_length = data[offset]
        offset += 1

        # Make sure the complete source address exists
        if len(data) < offset + source_length:
            return None

        # SADR: Source Address
        source_address = data[
            offset:offset + source_length
        ]
        offset += source_length

    # Hop count appears after the destination and source fields
    # when destination information is present
    if destination_present:

        if len(data) < offset + 1:
            return None

        hop_count = data[offset]
        offset += 1

    # Everything remaining is either a network-layer message
    # or an APDU
    remaining_data = data[offset:]

    if not remaining_data:
        return None

    if network_layer_message:
        network_message_type = remaining_data[0]
        network_message_data = remaining_data[1:]
        apdu_result = None

    else:
        network_message_type = None
        network_message_data = None
        apdu_result = process_apdu(remaining_data)

    return {
        "npdu_version": npdu_version,
        "network_layer_message": network_layer_message,
        "destination_present": destination_present,
        "source_present": source_present,
        "expecting_reply": expecting_reply,
        "priority": priority,

        "destination_network": destination_network,
        "destination_length": destination_length,
        "destination_address": (
            destination_address.hex()
            if destination_address is not None
            else None
        ),

        "source_network": source_network,
        "source_length": source_length,
        "source_address": (
            source_address.hex()
            if source_address is not None
            else None
        ),

        "hop_count": hop_count,

        "network_message_type": network_message_type,
        "network_message_data": network_message_data,
        "apdu": apdu_result,
    }
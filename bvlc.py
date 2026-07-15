from ipaddress import IPv4Address
from constants import (
    BVLC_FUNCTIONS,
    BVLC_RESULT_CODES,
    BVLC_TYPES,
)
from npdu import process_npdu

#---BLVC FUNCTION PROCESSORS---
def process_result(data: bytes) -> str | None:

    #0x00: "BVLC Result"
    # For this function, the body must contain only 2 bytes
    if len(data) != 2:
        return None

    result_code = int.from_bytes(data[0:2], "big")

    result = BVLC_RESULT_CODES.get(result_code, "Unknown BVLC Result Code")

    return(result)

def process_bdt(data: bytes) -> list[dict] | None:

    #0x01: "Write Broadcast Distribution Table"
    #0x03: "Read Broadcast Distribution Table ACK"

    #The body of these requests will always be made up of 10-byte BDT entries
    if len(data) % 10 != 0:
        return

    entries = []

    #since every entry is exactly 10 bytes, we enumerate them by increasing the offset each time
    #warning: AI wrote some of this
    for offset in range(0, len(data), 10):
        entry = data[offset:offset + 10]

        ip_address = str(IPv4Address(entry[0:4]))
        udp_port = int.from_bytes(entry[4:6], "big")
        broadcast_mask = str(IPv4Address(entry[6:10]))

        entries.append({
            "ip_address": ip_address,
            "udp_port": udp_port,
            "broadcast_mask": broadcast_mask,
        }
    )
        
    return entries
 
def process_no_body(data: bytes) -> bool:

    #0x02: "Read Broadcast Distribution Table"
    #0x06 — "Read Foreign Device Table"
    return len(data) == 0
    
def process_forwarded_npdu(data: bytes) -> dict | None:
    
    if len(data) < 8:
        return None

    originating_ip = str(IPv4Address(data[0:4]))
    originating_port = int.from_bytes(data[4:6], "big")

    npdu_data = data[6:]

    npdu_result = process_npdu(npdu_data)

    return {
        "originating_ip": originating_ip,
        "originating_port": originating_port,
        "npdu": npdu_result,
    }

def process_foreign_device_registration(data: bytes) -> dict | None:
    
    #0x05 — "Register Foreign Device"

    if len(data) != 2:
        return None

    ttl = int.from_bytes(data[0:2], "big")

    return {
        "foreign_device_ttl": ttl,
    }

def process_fdt(data: bytes) -> list[dict] | None:
    
    #0x07 — "Read Foreign Device Table ACK"

    # Every FDT entry is exactly 10 bytes
    if len(data) % 10 != 0:
        return None

    entries = []

    for offset in range(0, len(data), 10):
        entry = data[offset:offset + 10]

        foreign_device_ip = str(IPv4Address(entry[0:4]))
        foreign_device_port = int.from_bytes(entry[4:6], "big")
        ttl = int.from_bytes(entry[6:8], "big")
        seconds_remaining = int.from_bytes(entry[8:10], "big")

        entries.append({
            "foreign_device_ip": foreign_device_ip,
            "foreign_device_port": foreign_device_port,
            "ttl": ttl,
            "seconds_remaining": seconds_remaining,
        })

    return entries
    
def process_delete_fdt_entry(data: bytes) -> dict | None:
    
    if len(data) != 6:
        return None

    foreign_device_ip = str(IPv4Address(data[0:4]))
    foreign_device_port = int.from_bytes(data[4:6], "big")

    return {
        "foreign_device_ip": foreign_device_ip,
        "foreign_device_port": foreign_device_port,
    }
    
def process_secure_bvll(data: bytes) -> dict | None:

    # 0x0C: "Secure BVLL"
    #
    # At this point, data contains only the Security Wrapper.
    # The four-byte BVLC header has already been removed.

    # We need at least:
    # 1 byte for the security control field
    # 16 bytes for the required signature
    if len(data) < 17:
        return None

    security_control = data[0]

    # Extract Security Wrapper control flags
    network_or_secure_bvll = bool(security_control & 0x80)
    encrypted = bool(security_control & 0x40)
    reserved = bool(security_control & 0x20)
    authentication_present = bool(security_control & 0x10)
    do_not_unwrap = bool(security_control & 0x08)
    do_not_decrypt = bool(security_control & 0x04)
    non_trusted_source = bool(security_control & 0x02)
    secured_by_router = bool(security_control & 0x01)

    # The signature is the final 16 bytes of the wrapper
    signature = data[-16:]

    # Preserve everything between the control byte and signature.
    # We can process the complete Security Wrapper later.
    secured_data = data[1:-16]

    return {
        "security_control": security_control,
        "network_or_secure_bvll": network_or_secure_bvll,
        "encrypted": encrypted,
        "reserved": reserved,
        "authentication_present": authentication_present,
        "do_not_unwrap": do_not_unwrap,
        "do_not_decrypt": do_not_decrypt,
        "non_trusted_source": non_trusted_source,
        "secured_by_router": secured_by_router,
        "secured_data": secured_data,
        "signature": signature.hex(),
    }

#---BLVC HEADER PROCESSOR---
def process_bvlc(data: bytes) -> dict | None:

    # --- HEADER ---
    # A BVLC header contains type, function, and length.
    # Types and functions can be observed in the constants section.
    # A complete BVLC header is 4 bytes
    if len(data) < 4:
        return None
    
    # BVLC type
    type_code = data[0]
    type_name = BVLC_TYPES.get(type_code, "Unknown BVLC Type")

    # This function table and dispatcher only support BACnet/IPv4
    if type_code != 0x81:
        return None

    # BVLC function
    function_code = data[1]
    function_name = BVLC_FUNCTIONS.get(
        function_code,
        "Unknown BVLC Function"
    )

    bvlc_length = int.from_bytes(data[2:4], "big")
    length_valid = bvlc_length == len(data)

    # A declared BVLC length cannot be smaller than its header
    if bvlc_length < 4:
        return None
    
    # Do not attempt to parse an invalid declared length
    if not length_valid:
        return None
    
    # --- BODY ---
    body = data[4:bvlc_length]
    processor = BVLC_PROCESSORS.get(function_code)

    if processor is None:
        body_result = None
    else:
        body_result = processor(body)

    return {
        "bvlc_type_code": type_code,
        "bvlc_type": type_name,
        "bvlc_function_code": function_code,
        "bvlc_function": function_name,
        "bvlc_declared_length": bvlc_length,
        "bvlc_actual_length": len(data),
        "bvlc_length_valid": length_valid,
        "bvlc_body": body_result,
    }

BVLC_PROCESSORS = {
    0x00: process_result,
    0x01: process_bdt,
    0x02: process_no_body,
    0x03: process_bdt,
    0x04: process_forwarded_npdu,
    0x05: process_foreign_device_registration,
    0x06: process_no_body,
    0x07: process_fdt,
    0x08: process_delete_fdt_entry,
    0x09: process_npdu,
    0x0A: process_npdu,
    0x0B: process_npdu,
    0x0C: process_secure_bvll,
}
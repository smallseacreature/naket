"""Protocol constants used by the BACnet packet parser.

The numeric values in this module are kept separate from parsing logic so the
parser, database seeding code, and future user interface all use the same
lookup data.
"""

from __future__ import annotations

from typing import Final


# ---------------------------------------------------------------------------
# General BACnet values
# ---------------------------------------------------------------------------

BACNET_PROTOCOL_VERSION: Final[int] = 0x01
BACNET_IP_DEFAULT_UDP_PORT: Final[int] = 47_808


# ---------------------------------------------------------------------------
# BACnet Virtual Link Control (BVLC)
# ---------------------------------------------------------------------------

BVLC_TYPES: Final[dict[int, str]] = {
    0x81: "BACnet/IP over IPv4",
    0x82: "BACnet/IP over IPv6",
}

# Annex J: BACnet/IP over IPv4
BVLC_IPV4_FUNCTIONS: Final[dict[int, str]] = {
    0x00: "BVLC-Result",
    0x01: "Write-Broadcast-Distribution-Table",
    0x02: "Read-Broadcast-Distribution-Table",
    0x03: "Read-Broadcast-Distribution-Table-Ack",
    0x04: "Forwarded-NPDU",
    0x05: "Register-Foreign-Device",
    0x06: "Read-Foreign-Device-Table",
    0x07: "Read-Foreign-Device-Table-Ack",
    0x08: "Delete-Foreign-Device-Table-Entry",
    0x09: "Distribute-Broadcast-To-Network",
    0x0A: "Original-Unicast-NPDU",
    0x0B: "Original-Broadcast-NPDU",
    0x0C: "Secure-BVLL",
}

# Annex U: BACnet/IP over IPv6
BVLC_IPV6_FUNCTIONS: Final[dict[int, str]] = {
    0x00: "BVLC-Result",
    0x01: "Original-Unicast-NPDU",
    0x02: "Original-Broadcast-NPDU",
    0x03: "Address-Resolution",
    0x04: "Forwarded-Address-Resolution",
    0x05: "Address-Resolution-Ack",
    0x06: "Virtual-Address-Resolution",
    0x07: "Virtual-Address-Resolution-Ack",
    0x08: "Forwarded-NPDU",
    0x09: "Register-Foreign-Device",
    0x0A: "Delete-Foreign-Device-Table-Entry",
    0x0B: "Secure-BVLL",
    0x0C: "Distribute-Broadcast-To-Network",
}

# Function codes must be qualified by BVLC type. For example, function 0x01
# means Write-Broadcast-Distribution-Table for IPv4 but Original-Unicast-NPDU
# for IPv6.
BVLC_FUNCTIONS: Final[dict[tuple[int, int], str]] = {
    **{
        (0x81, function_code): function_name
        for function_code, function_name in BVLC_IPV4_FUNCTIONS.items()
    },
    **{
        (0x82, function_code): function_name
        for function_code, function_name in BVLC_IPV6_FUNCTIONS.items()
    },
}

BVLC_IPV4_RESULT_CODES: Final[dict[int, str]] = {
    0x0000: "Successful completion",
    0x0010: "Write-Broadcast-Distribution-Table NAK",
    0x0020: "Read-Broadcast-Distribution-Table NAK",
    0x0030: "Register-Foreign-Device NAK",
    0x0040: "Read-Foreign-Device-Table NAK",
    0x0050: "Delete-Foreign-Device-Table-Entry NAK",
    0x0060: "Distribute-Broadcast-To-Network NAK",
}

BVLC_IPV6_RESULT_CODES: Final[dict[int, str]] = {
    0x0000: "Successful completion",
    0x0030: "Address-Resolution NAK",
    0x0060: "Virtual-Address-Resolution NAK",
    0x0090: "Register-Foreign-Device NAK",
    0x00A0: "Delete-Foreign-Device-Table-Entry NAK",
    0x00C0: "Distribute-Broadcast-To-Network NAK",
}

# Result codes also need the BVLC type because some numeric values have
# different meanings between IPv4 and IPv6.
BVLC_RESULT_CODES: Final[dict[tuple[int, int], str]] = {
    **{
        (0x81, result_code): result_name
        for result_code, result_name in BVLC_IPV4_RESULT_CODES.items()
    },
    **{
        (0x82, result_code): result_name
        for result_code, result_name in BVLC_IPV6_RESULT_CODES.items()
    },
}


def get_bvlc_function_name(type_code: int, function_code: int) -> str:
    """Return a BVLC function name without confusing IPv4 and IPv6 codes."""
    return BVLC_FUNCTIONS.get(
        (type_code, function_code),
        "Unknown BVLC Function",
    )


def get_bvlc_result_name(type_code: int, result_code: int) -> str:
    """Return a BVLC result name qualified by the BVLC type."""
    return BVLC_RESULT_CODES.get(
        (type_code, result_code),
        "Unknown BVLC Result Code",
    )


# ---------------------------------------------------------------------------
# Network Protocol Data Unit (NPDU)
# ---------------------------------------------------------------------------

NPDU_PRIORITIES: Final[dict[int, str]] = {
    0x00: "Normal",
    0x01: "Urgent",
    0x02: "Critical Equipment",
    0x03: "Life Safety",
}

NPDU_NETWORK_MESSAGES: Final[dict[int, str]] = {
    0x00: "Who-Is-Router-To-Network",
    0x01: "I-Am-Router-To-Network",
    0x02: "I-Could-Be-Router-To-Network",
    0x03: "Reject-Message-To-Network",
    0x04: "Router-Busy-To-Network",
    0x05: "Router-Available-To-Network",
    0x06: "Initialize-Routing-Table",
    0x07: "Initialize-Routing-Table-Ack",
    0x08: "Establish-Connection-To-Network",
    0x09: "Disconnect-Connection-To-Network",
    0x0A: "Challenge-Request",
    0x0B: "Security-Payload",
    0x0C: "Security-Response",
    0x0D: "Request-Key-Update",
    0x0E: "Update-Key-Set",
    0x0F: "Update-Distribution-Key",
    0x10: "Request-Master-Key",
    0x11: "Set-Master-Key",
    0x12: "What-Is-Network-Number",
    0x13: "Network-Number-Is",
}

NPDU_PROPRIETARY_MESSAGE_MIN: Final[int] = 0x80
NPDU_PROPRIETARY_MESSAGE_MAX: Final[int] = 0xFF


# ---------------------------------------------------------------------------
# Application Protocol Data Unit (APDU)
# ---------------------------------------------------------------------------

APDU_TYPES: Final[dict[int, str]] = {
    0x00: "Confirmed Request",
    0x01: "Unconfirmed Request",
    0x02: "Simple ACK",
    0x03: "Complex ACK",
    0x04: "Segment ACK",
    0x05: "Error",
    0x06: "Reject",
    0x07: "Abort",
}

# Encoded values from the upper three bits of the second byte of a
# Confirmed-Request APDU.
APDU_MAX_SEGMENTS_ACCEPTED: Final[dict[int, str]] = {
    0x00: "Unspecified",
    0x01: "2 segments",
    0x02: "4 segments",
    0x03: "8 segments",
    0x04: "16 segments",
    0x05: "32 segments",
    0x06: "64 segments",
    0x07: "More than 64 segments",
}

# Encoded values from the lower four bits of the second byte of a
# Confirmed-Request APDU. Codes 6 through 15 are reserved.
APDU_MAX_LENGTH_ACCEPTED: Final[dict[int, int]] = {
    0x00: 50,
    0x01: 128,
    0x02: 206,
    0x03: 480,
    0x04: 1_024,
    0x05: 1_476,
}

# Services that use a Confirmed-Request APDU and therefore expect a response.
CONFIRMED_SERVICES: Final[dict[int, str]] = {
    0: "AcknowledgeAlarm",
    1: "ConfirmedCOVNotification",
    2: "ConfirmedEventNotification",
    3: "GetAlarmSummary",
    4: "GetEnrollmentSummary",
    5: "SubscribeCOV",
    6: "AtomicReadFile",
    7: "AtomicWriteFile",
    8: "AddListElement",
    9: "RemoveListElement",
    10: "CreateObject",
    11: "DeleteObject",
    12: "ReadProperty",
    13: "ReadPropertyConditional",
    14: "ReadPropertyMultiple",
    15: "WriteProperty",
    16: "WritePropertyMultiple",
    17: "DeviceCommunicationControl",
    18: "ConfirmedPrivateTransfer",
    19: "ConfirmedTextMessage",
    20: "ReinitializeDevice",
    21: "VTOpen",
    22: "VTClose",
    23: "VTData",
    24: "Authenticate",
    25: "RequestKey",
    26: "ReadRange",
    27: "LifeSafetyOperation",
    28: "SubscribeCOVProperty",
    29: "GetEventInformation",
    30: "SubscribeCOVPropertyMultiple",
    31: "ConfirmedCOVNotificationMultiple",
    32: "ConfirmedAuditNotification",
    33: "AuditLogQuery",
}

# Services that use an Unconfirmed-Request APDU and do not receive an ACK.
UNCONFIRMED_SERVICES: Final[dict[int, str]] = {
    0: "I-Am",
    1: "I-Have",
    2: "UnconfirmedCOVNotification",
    3: "UnconfirmedEventNotification",
    4: "UnconfirmedPrivateTransfer",
    5: "UnconfirmedTextMessage",
    6: "TimeSynchronization",
    7: "Who-Has",
    8: "Who-Is",
    9: "UTCTimeSynchronization",
    10: "WriteGroup",
    11: "UnconfirmedCOVNotificationMultiple",
    12: "UnconfirmedAuditNotification",
    13: "Who-Am-I",
    14: "You-Are",
}
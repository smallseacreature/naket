

#---BLVC---
BVLC_TYPES = {
    0x81: "BACnet/IP over IPv4",
    0x82: "BACnet/IPv6",
}

BVLC_FUNCTIONS = {
    0x00: "BVLC Result",
    0x01: "Write Broadcast Distribution Table",
    0x02: "Read Broadcast Distribution Table",
    0x03: "Read Broadcast Distribution Table ACK",
    0x04: "Forwarded NPDU",
    0x05: "Register Foreign Device",
    0x06: "Read Foreign Device Table",
    0x07: "Read Foreign Device Table ACK",
    0x08: "Delete Foreign Device Table Entry",
    0x09: "Distribute Broadcast to Network",
    0x0A: "Original Unicast NPDU",
    0x0B: "Original Broadcast NPDU",
    0x0C: "Secure BVLL",
}

BVLC_RESULT_CODES = {
    0x0000: "Successful completion",
    0x0010: "Write BDT NAK",
    0x0020: "Read BDT NAK",
    0x0030: "Register Foreign Device NAK",
    0x0040: "Read FDT NAK",
    0x0050: "Delete FDT Entry NAK",
    0x0060: "Distribute Broadcast NAK",
}


#---APDU---

APDU_TYPES = {
    0x00: "Confirmed Request",
    0x01: "Unconfirmed Request",
    0x02: "Simple ACK",
    0x03: "Complex ACK",
    0x04: "Segment ACK",
    0x05: "Error",
    0x06: "Reject",
    0x07: "Abort",
}

#services that expect a confirmation message
CONFIRMED_SERVICES = {
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

#services that do not expect confirmation messages
UNCONFIRMED_SERVICES = {
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

#---NPDU---

NPDU_PRIORITIES = {
    0: "Normal",
    1: "Urgent",
    2: "Critical Equipment",
    3: "Life Safety",
}


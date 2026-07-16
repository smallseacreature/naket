"""BACnet confirmed-service conversation tracking and APDU reassembly.

This module groups Confirmed-Request, ACK, Error, Reject, Abort, and SegmentACK
packets into logical BACnet conversations.  It also reassembles segmented
Confirmed-Request and ComplexACK service payloads so callers can decode one
complete operation instead of treating each APDU packet independently.

The tracker is intentionally database-agnostic.  It accepts mappings containing
the normalized APDU, IP, UDP, packet-number, and timestamp fields already stored
by this project.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence


READ_SERVICE_CHOICES = frozenset({6, 12, 14})
WRITE_SERVICE_CHOICES = frozenset({7, 15, 16})
READ_WRITE_SERVICE_CHOICES = READ_SERVICE_CHOICES | WRITE_SERVICE_CHOICES

PDU_CONFIRMED_REQUEST = 0
PDU_SIMPLE_ACK = 2
PDU_COMPLEX_ACK = 3
PDU_SEGMENT_ACK = 4
PDU_ERROR = 5
PDU_REJECT = 6
PDU_ABORT = 7

_RESPONSE_WITH_SERVICE = frozenset({PDU_SIMPLE_ACK, PDU_COMPLEX_ACK, PDU_ERROR})
_TERMINAL_RESPONSE_TYPES = frozenset(
    {PDU_SIMPLE_ACK, PDU_COMPLEX_ACK, PDU_ERROR, PDU_REJECT, PDU_ABORT}
)


PacketRow = Mapping[str, Any]
ConversationKey = tuple[int, str, int | None, str, int | None, int]


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    return int(value)


def _bool(value: Any) -> bool:
    return bool(int(value)) if isinstance(value, int) else bool(value)


def _raw_payload(row: PacketRow) -> bytes:
    value = row.get("raw_service_data")
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise TypeError(
        "raw_service_data must be bytes-like or None, "
        f"received {type(value).__name__}"
    )


def _packet_sort_key(row: PacketRow) -> tuple[float, int, int]:
    return (
        float(row.get("timestamp") or 0.0),
        int(row.get("capture_id") or 0),
        int(row.get("packet_number") or 0),
    )


def _endpoint_key(row: PacketRow, *, reverse: bool = False) -> ConversationKey:
    source_ip = str(row.get("source_ip") or "")
    destination_ip = str(row.get("destination_ip") or "")
    source_port = _optional_int(row.get("source_port"))
    destination_port = _optional_int(row.get("destination_port"))

    if reverse:
        source_ip, destination_ip = destination_ip, source_ip
        source_port, destination_port = destination_port, source_port

    invoke_id = _optional_int(row.get("invoke_id"))
    if invoke_id is None:
        raise ValueError("Confirmed BACnet conversation packet has no invoke_id")

    return (
        int(row.get("capture_id") or 0),
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        invoke_id,
    )


def _same_unsegmented_message(first: PacketRow, second: PacketRow) -> bool:
    return (
        int(first.get("pdu_type_code", -1))
        == int(second.get("pdu_type_code", -1))
        and _optional_int(first.get("service_choice"))
        == _optional_int(second.get("service_choice"))
        and _raw_payload(first) == _raw_payload(second)
    )


@dataclass
class MessageAssembly:
    """One request or response APDU, possibly spread across many segments."""

    pdu_type_code: int
    service_choice: int | None
    packets: list[PacketRow] = field(default_factory=list)
    duplicate_packet_ids: list[int] = field(default_factory=list)
    conflicting_sequences: set[int] = field(default_factory=set)

    def add(self, row: PacketRow) -> None:
        """Add one packet, suppressing exact retransmissions."""
        pdu_type = int(row.get("pdu_type_code", -1))
        if pdu_type != self.pdu_type_code:
            raise ValueError(
                f"Cannot add PDU type {pdu_type} to type {self.pdu_type_code} assembly"
            )

        row_service = _optional_int(row.get("service_choice"))
        if (
            self.service_choice is not None
            and row_service is not None
            and row_service != self.service_choice
        ):
            raise ValueError(
                "Cannot combine segmented APDUs with different service choices"
            )

        if self.service_choice is None and row_service is not None:
            self.service_choice = row_service

        segmented = _bool(row.get("segmented_message"))
        sequence = _optional_int(row.get("sequence_number")) if segmented else None

        for existing in self.packets:
            existing_segmented = _bool(existing.get("segmented_message"))
            existing_sequence = (
                _optional_int(existing.get("sequence_number"))
                if existing_segmented
                else None
            )

            if sequence == existing_sequence:
                if _raw_payload(existing) == _raw_payload(row):
                    packet_id = _optional_int(row.get("packet_id"))
                    if packet_id is not None:
                        self.duplicate_packet_ids.append(packet_id)
                    return

                if sequence is not None:
                    self.conflicting_sequences.add(sequence)
                    # Keep the first captured version for deterministic output.
                    return

                if _same_unsegmented_message(existing, row):
                    packet_id = _optional_int(row.get("packet_id"))
                    if packet_id is not None:
                        self.duplicate_packet_ids.append(packet_id)
                    return

        self.packets.append(row)
        self.packets.sort(key=_packet_sort_key)

    @property
    def segmented(self) -> bool:
        return any(_bool(row.get("segmented_message")) for row in self.packets)

    @property
    def final_segment_seen(self) -> bool:
        if not self.segmented:
            return bool(self.packets)
        return any(not _bool(row.get("more_follows")) for row in self.packets)

    def _unique_segment_rows(self) -> list[PacketRow]:
        if not self.segmented:
            return self.packets[:1]

        by_sequence: dict[int, PacketRow] = {}
        for row in self.packets:
            sequence = _optional_int(row.get("sequence_number"))
            if sequence is not None and sequence not in by_sequence:
                by_sequence[sequence] = row

        if not by_sequence:
            return []

        ordered: list[PacketRow] = []
        current = 0
        visited = 0
        while current in by_sequence and visited <= 256:
            row = by_sequence[current]
            ordered.append(row)
            visited += 1
            if not _bool(row.get("more_follows")):
                break
            current = (current + 1) & 0xFF

        return ordered

    @property
    def missing_sequences(self) -> tuple[int, ...]:
        if not self.segmented or not self.packets:
            return ()

        by_sequence = {
            sequence
            for row in self.packets
            if (sequence := _optional_int(row.get("sequence_number"))) is not None
        }
        if not by_sequence:
            return (0,)

        final_sequences = [
            _optional_int(row.get("sequence_number"))
            for row in self.packets
            if not _bool(row.get("more_follows"))
        ]
        final_sequences = [value for value in final_sequences if value is not None]

        # Without a final segment we can only state that the next sequence after
        # the contiguous prefix is missing.
        if not final_sequences:
            current = 0
            while current in by_sequence and current < 255:
                current += 1
            return (current,)

        final_sequence = final_sequences[0]
        missing: list[int] = []
        current = 0
        for _ in range(256):
            if current not in by_sequence:
                missing.append(current)
            if current == final_sequence:
                break
            current = (current + 1) & 0xFF
        return tuple(missing)

    @property
    def complete(self) -> bool:
        if not self.packets:
            return False
        if not self.segmented:
            return True
        return (
            self.final_segment_seen
            and not self.missing_sequences
            and not self.conflicting_sequences
            and bool(self._unique_segment_rows())
        )

    @property
    def payload(self) -> bytes:
        rows = self._unique_segment_rows() if self.segmented else self.packets[:1]
        return b"".join(_raw_payload(row) for row in rows)

    @property
    def first_packet(self) -> PacketRow | None:
        return self.packets[0] if self.packets else None

    @property
    def last_packet(self) -> PacketRow | None:
        return self.packets[-1] if self.packets else None

    @property
    def packet_ids(self) -> tuple[int, ...]:
        return tuple(
            int(row["packet_id"])
            for row in self.packets
            if row.get("packet_id") is not None
        )

    @property
    def packet_numbers(self) -> tuple[int, ...]:
        return tuple(
            int(row["packet_number"])
            for row in self.packets
            if row.get("packet_number") is not None
        )


@dataclass
class BacnetConversation:
    """A logical confirmed BACnet request and its response."""

    conversation_id: int
    key: ConversationKey
    service_choice: int
    service_name: str
    request: MessageAssembly | None = None
    response: MessageAssembly | None = None
    terminal_packet: PacketRow | None = None
    segment_ack_packets: list[PacketRow] = field(default_factory=list)
    orphan_response: bool = False

    @property
    def capture_id(self) -> int:
        return self.key[0]

    @property
    def client_ip(self) -> str:
        return self.key[1]

    @property
    def client_port(self) -> int | None:
        return self.key[2]

    @property
    def server_ip(self) -> str:
        return self.key[3]

    @property
    def server_port(self) -> int | None:
        return self.key[4]

    @property
    def invoke_id(self) -> int:
        return self.key[5]

    @property
    def response_pdu_type(self) -> int | None:
        if self.response is not None:
            return self.response.pdu_type_code
        if self.terminal_packet is not None:
            return int(self.terminal_packet.get("pdu_type_code", -1))
        return None

    @property
    def response_complete(self) -> bool:
        if self.response is not None:
            return self.response.complete
        return self.terminal_packet is not None

    @property
    def request_complete(self) -> bool:
        return self.request is not None and self.request.complete

    @property
    def closed(self) -> bool:
        return self.response_complete

    @property
    def incomplete_segmented(self) -> bool:
        return bool(
            (self.request and self.request.segmented and not self.request.complete)
            or (self.response and self.response.segmented and not self.response.complete)
        )

    @property
    def start_timestamp(self) -> float | None:
        packets = self.all_packets
        if not packets:
            return None
        return min(float(row.get("timestamp") or 0.0) for row in packets)

    @property
    def end_timestamp(self) -> float | None:
        packets = self.all_packets
        if not packets:
            return None
        return max(float(row.get("timestamp") or 0.0) for row in packets)

    @property
    def all_packets(self) -> list[PacketRow]:
        packets: list[PacketRow] = []
        if self.request is not None:
            packets.extend(self.request.packets)
        if self.response is not None:
            packets.extend(self.response.packets)
        if self.terminal_packet is not None:
            packets.append(self.terminal_packet)
        packets.extend(self.segment_ack_packets)
        return sorted(packets, key=_packet_sort_key)

    @property
    def request_payload(self) -> bytes:
        return b"" if self.request is None else self.request.payload

    @property
    def response_payload(self) -> bytes:
        return b"" if self.response is None else self.response.payload

    @property
    def request_packet_numbers(self) -> tuple[int, ...]:
        return () if self.request is None else self.request.packet_numbers

    @property
    def response_packet_numbers(self) -> tuple[int, ...]:
        if self.response is not None:
            return self.response.packet_numbers
        if self.terminal_packet is not None and self.terminal_packet.get("packet_number") is not None:
            return (int(self.terminal_packet["packet_number"]),)
        return ()

    @property
    def status(self) -> str:
        if self.incomplete_segmented:
            return "incomplete-segments"
        if self.terminal_packet is not None:
            return {
                PDU_REJECT: "rejected",
                PDU_ABORT: "aborted",
            }.get(int(self.terminal_packet.get("pdu_type_code", -1)), "closed")
        if self.response is None:
            return "no-response"
        if self.response.pdu_type_code == PDU_ERROR:
            return "error"
        if self.response.pdu_type_code == PDU_SIMPLE_ACK:
            return "acknowledged"
        if self.response.pdu_type_code == PDU_COMPLEX_ACK:
            return "response"
        return "closed"


def _find_open_conversation(
    open_conversations: dict[ConversationKey, list[BacnetConversation]],
    key: ConversationKey,
    *,
    service_choice: int | None = None,
) -> BacnetConversation | None:
    candidates = open_conversations.get(key, [])
    for conversation in reversed(candidates):
        if conversation.closed:
            continue
        if service_choice is not None and conversation.service_choice != service_choice:
            continue
        return conversation
    return None


def _remove_closed(
    open_conversations: dict[ConversationKey, list[BacnetConversation]],
    conversation: BacnetConversation,
) -> None:
    candidates = open_conversations.get(conversation.key)
    if not candidates:
        return
    open_conversations[conversation.key] = [
        item for item in candidates if item is not conversation
    ]
    if not open_conversations[conversation.key]:
        del open_conversations[conversation.key]


def build_bacnet_conversations(
    rows: Iterable[PacketRow],
    *,
    service_choices: Sequence[int] | None = None,
) -> list[BacnetConversation]:
    """Group normalized APDU rows into confirmed-service conversations.

    Args:
        rows: APDU rows ordered arbitrarily.  Required fields include capture,
            endpoint, invoke-ID, PDU type, service choice, segmentation fields,
            and raw service data.
        service_choices: Optional confirmed-service allowlist.  Responses,
            SegmentACKs, Rejects, and Aborts are still considered so they can
            close matching allowed requests.
    """
    allowed = (
        None
        if service_choices is None
        else frozenset(int(choice) for choice in service_choices)
    )

    normalized_rows = [dict(row) for row in rows]
    sorted_rows = sorted(normalized_rows, key=_packet_sort_key)
    conversations: list[BacnetConversation] = []
    open_conversations: dict[ConversationKey, list[BacnetConversation]] = {}
    orphan_responses: dict[tuple[ConversationKey, int, int], BacnetConversation] = {}
    next_id = 1

    for row in sorted_rows:
        pdu_type = int(row.get("pdu_type_code", -1))
        invoke_id = _optional_int(row.get("invoke_id"))
        if invoke_id is None:
            continue

        service_choice = _optional_int(row.get("service_choice"))
        service_name = str(row.get("service_name") or "Unknown Service")

        if pdu_type == PDU_CONFIRMED_REQUEST:
            if service_choice is None:
                continue
            if allowed is not None and service_choice not in allowed:
                continue

            key = _endpoint_key(row)
            segmented = _bool(row.get("segmented_message"))
            sequence = _optional_int(row.get("sequence_number")) if segmented else None
            existing = _find_open_conversation(
                open_conversations,
                key,
                service_choice=service_choice,
            )

            use_existing = False
            if existing is not None and existing.request is not None:
                if segmented:
                    # Sequence zero may be a retransmission of the first segment;
                    # later sequence numbers continue the same request.
                    use_existing = not existing.request.complete
                    if sequence == 0 and existing.request.complete:
                        use_existing = False
                elif not existing.request.complete:
                    use_existing = True
                elif existing.response is None and existing.terminal_packet is None:
                    first = existing.request.first_packet
                    use_existing = bool(
                        first is not None and _same_unsegmented_message(first, row)
                    )

            if not use_existing:
                existing = BacnetConversation(
                    conversation_id=next_id,
                    key=key,
                    service_choice=service_choice,
                    service_name=service_name,
                    request=MessageAssembly(
                        pdu_type_code=PDU_CONFIRMED_REQUEST,
                        service_choice=service_choice,
                    ),
                )
                next_id += 1
                conversations.append(existing)
                open_conversations.setdefault(key, []).append(existing)

            assert existing.request is not None
            existing.request.add(row)
            continue

        if pdu_type in _RESPONSE_WITH_SERVICE:
            if service_choice is None:
                continue
            if allowed is not None and service_choice not in allowed:
                # It may still be a response to an allowed request only when the
                # service matches, so no useful match is possible here.
                continue

            key = _endpoint_key(row, reverse=True)
            conversation = _find_open_conversation(
                open_conversations,
                key,
                service_choice=service_choice,
            )

            if conversation is None:
                orphan_key = (key, service_choice, pdu_type)
                conversation = orphan_responses.get(orphan_key)
                if conversation is None or conversation.closed:
                    conversation = BacnetConversation(
                        conversation_id=next_id,
                        key=key,
                        service_choice=service_choice,
                        service_name=service_name,
                        orphan_response=True,
                    )
                    next_id += 1
                    conversations.append(conversation)
                    orphan_responses[orphan_key] = conversation

            if conversation.response is None:
                conversation.response = MessageAssembly(
                    pdu_type_code=pdu_type,
                    service_choice=service_choice,
                )
            elif conversation.response.pdu_type_code != pdu_type:
                # An Error after a partial ComplexACK, for example, terminates
                # the transaction and should not be merged into response bytes.
                conversation.terminal_packet = row
                _remove_closed(open_conversations, conversation)
                continue

            conversation.response.add(row)
            if conversation.response.complete:
                _remove_closed(open_conversations, conversation)
            continue

        if pdu_type in (PDU_REJECT, PDU_ABORT):
            key = _endpoint_key(row, reverse=True)
            conversation = _find_open_conversation(open_conversations, key)
            if conversation is not None:
                conversation.terminal_packet = row
                _remove_closed(open_conversations, conversation)
            continue

        if pdu_type == PDU_SEGMENT_ACK:
            # SegmentACK direction is opposite the segmented APDU being
            # acknowledged. Try both directions because captures can start in
            # the middle of a transaction and the SRV flag changes the sender.
            reverse_key = _endpoint_key(row, reverse=True)
            direct_key = _endpoint_key(row)
            conversation = _find_open_conversation(open_conversations, reverse_key)
            if conversation is None:
                conversation = _find_open_conversation(open_conversations, direct_key)
            if conversation is not None:
                conversation.segment_ack_packets.append(row)

    return sorted(
        conversations,
        key=lambda conversation: (
            conversation.start_timestamp or 0.0,
            conversation.capture_id,
            conversation.conversation_id,
        ),
    )


def conversation_summary(conversation: BacnetConversation) -> dict[str, Any]:
    """Return a serialization-friendly diagnostic summary."""
    return {
        "conversation_id": conversation.conversation_id,
        "capture_id": conversation.capture_id,
        "client_ip": conversation.client_ip,
        "client_port": conversation.client_port,
        "server_ip": conversation.server_ip,
        "server_port": conversation.server_port,
        "invoke_id": conversation.invoke_id,
        "service_choice": conversation.service_choice,
        "service_name": conversation.service_name,
        "status": conversation.status,
        "request_segmented": bool(
            conversation.request and conversation.request.segmented
        ),
        "request_complete": conversation.request_complete,
        "request_missing_sequences": (
            ()
            if conversation.request is None
            else conversation.request.missing_sequences
        ),
        "response_segmented": bool(
            conversation.response and conversation.response.segmented
        ),
        "response_complete": conversation.response_complete,
        "response_missing_sequences": (
            ()
            if conversation.response is None
            else conversation.response.missing_sequences
        ),
        "request_packet_numbers": conversation.request_packet_numbers,
        "response_packet_numbers": conversation.response_packet_numbers,
        "request_payload_length": len(conversation.request_payload),
        "response_payload_length": len(conversation.response_payload),
        "duplicate_request_packets": (
            ()
            if conversation.request is None
            else tuple(conversation.request.duplicate_packet_ids)
        ),
        "duplicate_response_packets": (
            ()
            if conversation.response is None
            else tuple(conversation.response.duplicate_packet_ids)
        ),
    }

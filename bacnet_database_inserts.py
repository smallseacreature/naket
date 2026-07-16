"""Insertion helpers for the BACnet SQLite database.

The functions in this module accept the normalized dictionaries produced by
``layers.py``, ``bvlc.py``, ``npdu.py``, and ``apdu.py``.  They do not commit
individual rows.  Multi-row operations use transactions or savepoints so a
packet or capture is never left partially inserted.
"""

from __future__ import annotations

import itertools
import sqlite3
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from constants import (
    APDU_TYPES,
    BVLC_FUNCTIONS,
    BVLC_RESULT_CODES,
    BVLC_TYPES,
    CONFIRMED_SERVICES,
    NPDU_NETWORK_MESSAGES,
    NPDU_PRIORITIES,
    UNCONFIRMED_SERVICES,
)


PacketRecord = Mapping[str, Any]
LayerRecord = Mapping[str, Any]

_SAVEPOINT_COUNTER = itertools.count(1)


def _required(data: Mapping[str, Any], key: str, context: str) -> Any:
    """Return a required mapping value or raise a descriptive error."""
    if key not in data or data[key] is None:
        raise ValueError(f"Missing required {context} field: {key}")

    return data[key]


def _optional_mapping(
    value: Any,
    context: str,
) -> Mapping[str, Any] | None:
    """Validate an optional nested protocol record."""
    if value is None:
        return None

    if not isinstance(value, Mapping):
        raise TypeError(
            f"{context} data must be a mapping, "
            f"received {type(value).__name__}"
        )

    return value


def _bool_to_int(value: Any) -> int | None:
    """Convert a Boolean or SQLite-style 0/1 value to an integer."""
    if value is None:
        return None

    if isinstance(value, bool):
        return int(value)

    if isinstance(value, int) and value in (0, 1):
        return value

    raise TypeError(
        "Boolean database fields must be bool, 0, 1, or None; "
        f"received {value!r}"
    )


def _as_blob(value: Any) -> bytes | None:
    """Normalize bytes-like values for SQLite BLOB columns."""
    if value is None:
        return None

    if isinstance(value, bytes):
        return value

    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)

    raise TypeError(
        "Expected bytes-like data for a BLOB column, "
        f"received {type(value).__name__}"
    )


@contextmanager
def _atomic(
    connection: sqlite3.Connection,
    label: str,
) -> Iterator[None]:
    """Run a group of statements atomically without committing outer work.

    A top-level operation starts and commits its own transaction.  When the
    caller already has an active transaction, a uniquely named savepoint is
    used instead.  This allows functions such as ``insert_parsed_packet`` to be
    safely called both on their own and from a whole-capture transaction.
    """
    if connection.in_transaction:
        savepoint = f"{label}_{next(_SAVEPOINT_COUNTER)}"
        connection.execute(f'SAVEPOINT "{savepoint}"')

        try:
            yield
        except Exception:
            connection.execute(f'ROLLBACK TO SAVEPOINT "{savepoint}"')
            connection.execute(f'RELEASE SAVEPOINT "{savepoint}"')
            raise
        else:
            connection.execute(f'RELEASE SAVEPOINT "{savepoint}"')

        return

    connection.execute("BEGIN IMMEDIATE")

    try:
        yield
    except Exception:
        connection.rollback()
        raise
    else:
        connection.commit()


def insert_capture(
    connection: sqlite3.Connection,
    *,
    filename: str,
    file_sha256: str | None = None,
    capture_start: float | None = None,
    capture_end: float | None = None,
    packet_count: int | None = None,
    link_type: int | None = None,
    notes: str | None = None,
) -> int:
    """Insert one capture row and return its ``capture_id``.

    This low-level function does not commit.  Use
    :func:`insert_capture_with_packets` for a complete transactional import.
    """
    cursor = connection.execute(
        """
        INSERT INTO captures (
            filename,
            file_sha256,
            capture_start,
            capture_end,
            packet_count,
            link_type,
            notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            filename,
            file_sha256,
            capture_start,
            capture_end,
            packet_count,
            link_type,
            notes,
        ),
    )

    if cursor.lastrowid is None:
        raise sqlite3.DatabaseError(
            "Capture insert did not return a capture_id"
        )

    return int(cursor.lastrowid)


def insert_capture_metadata(
    connection: sqlite3.Connection,
    metadata: Mapping[str, Any],
    *,
    notes: str | None = None,
) -> int:
    """Insert the dictionary returned by ``capture.get_capture_metadata``."""
    return insert_capture(
        connection,
        filename=str(_required(metadata, "filename", "capture metadata")),
        file_sha256=metadata.get("file_sha256"),
        capture_start=metadata.get("capture_start"),
        capture_end=metadata.get("capture_end"),
        packet_count=metadata.get("packet_count"),
        link_type=metadata.get("link_type"),
        notes=notes,
    )


def insert_packet(
    connection: sqlite3.Connection,
    *,
    capture_id: int,
    packet_number: int,
    timestamp: float,
    captured_length: int | None = None,
    original_length: int | None = None,
    parse_status: str = "parsed",
    parse_notes: str | None = None,
    raw_packet: bytes | bytearray | memoryview | None = None,
) -> int:
    """Insert the base packet row and return its ``packet_id``."""
    cursor = connection.execute(
        """
        INSERT INTO packets (
            capture_id,
            packet_number,
            timestamp,
            captured_length,
            original_length,
            parse_status,
            parse_notes,
            raw_packet
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            capture_id,
            packet_number,
            timestamp,
            captured_length,
            original_length,
            parse_status,
            parse_notes,
            _as_blob(raw_packet),
        ),
    )

    if cursor.lastrowid is None:
        raise sqlite3.DatabaseError(
            "Packet insert did not return a packet_id"
        )

    return int(cursor.lastrowid)


def insert_ethernet_header(
    connection: sqlite3.Connection,
    packet_id: int,
    data: LayerRecord,
) -> None:
    """Insert one normalized Ethernet header."""
    connection.execute(
        """
        INSERT INTO ethernet_headers (
            packet_id,
            source_mac,
            destination_mac,
            ether_type
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            packet_id,
            _required(data, "source_mac", "Ethernet"),
            _required(data, "destination_mac", "Ethernet"),
            data.get("ether_type"),
        ),
    )


def insert_ip_header(
    connection: sqlite3.Connection,
    packet_id: int,
    data: LayerRecord,
) -> None:
    """Insert one normalized IPv4 header."""
    connection.execute(
        """
        INSERT INTO ip_headers (
            packet_id,
            ip_version,
            source_ip,
            destination_ip,
            protocol,
            ttl,
            identification,
            flags,
            fragment_offset,
            header_length,
            total_length,
            checksum
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            packet_id,
            _required(data, "ip_version", "IP"),
            _required(data, "source_ip", "IP"),
            _required(data, "destination_ip", "IP"),
            data.get("protocol"),
            data.get("ttl"),
            data.get("identification"),
            data.get("flags"),
            data.get("fragment_offset"),
            data.get("header_length"),
            data.get("total_length"),
            data.get("checksum"),
        ),
    )


def insert_udp_header(
    connection: sqlite3.Connection,
    packet_id: int,
    data: LayerRecord,
) -> None:
    """Insert one normalized UDP header."""
    connection.execute(
        """
        INSERT INTO udp_headers (
            packet_id,
            source_port,
            destination_port,
            udp_length,
            checksum
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            packet_id,
            _required(data, "source_port", "UDP"),
            _required(data, "destination_port", "UDP"),
            data.get("udp_length"),
            data.get("checksum"),
        ),
    )


def insert_bvlc_header(
    connection: sqlite3.Connection,
    packet_id: int,
    data: LayerRecord,
) -> None:
    """Insert one normalized BVLC header and body summary."""
    connection.execute(
        """
        INSERT INTO bvlc_headers (
            packet_id,
            bvlc_type_code,
            function_code,
            declared_length,
            actual_length,
            length_valid,
            body_parse_valid,
            parse_valid,
            body_parse_error,
            result_code,
            originating_ip,
            originating_port,
            registration_ttl,
            delete_ip,
            delete_port,
            security_control,
            security_wrapper_data,
            security_signature,
            raw_body,
            trailing_data,
            unsupported_reason
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            packet_id,
            _required(data, "bvlc_type_code", "BVLC"),
            _required(data, "function_code", "BVLC"),
            data.get("declared_length"),
            data.get("actual_length"),
            _bool_to_int(data.get("length_valid")),
            _bool_to_int(data.get("body_parse_valid")),
            _bool_to_int(_required(data, "parse_valid", "BVLC")),
            data.get("body_parse_error"),
            data.get("result_code"),
            data.get("originating_ip"),
            data.get("originating_port"),
            data.get("registration_ttl"),
            data.get("delete_ip"),
            data.get("delete_port"),
            data.get("security_control"),
            _as_blob(data.get("security_wrapper_data")),
            _as_blob(data.get("security_signature")),
            _as_blob(data.get("raw_body")),
            _as_blob(data.get("trailing_data")),
            data.get("unsupported_reason"),
        ),
    )


def insert_bdt_entries(
    connection: sqlite3.Connection,
    packet_id: int,
    entries: Iterable[LayerRecord],
) -> None:
    """Insert every Broadcast Distribution Table entry for one packet."""
    rows: list[tuple[Any, ...]] = []

    for default_number, entry in enumerate(entries):
        rows.append(
            (
                packet_id,
                entry.get("entry_number", default_number),
                _required(entry, "ip_address", "BDT entry"),
                _required(entry, "udp_port", "BDT entry"),
                entry.get("broadcast_mask"),
            )
        )

    if rows:
        connection.executemany(
            """
            INSERT INTO bvlc_bdt_entries (
                packet_id,
                entry_number,
                ip_address,
                udp_port,
                broadcast_mask
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            rows,
        )


def insert_fdt_entries(
    connection: sqlite3.Connection,
    packet_id: int,
    entries: Iterable[LayerRecord],
) -> None:
    """Insert every Foreign Device Table entry for one packet."""
    rows: list[tuple[Any, ...]] = []

    for default_number, entry in enumerate(entries):
        rows.append(
            (
                packet_id,
                entry.get("entry_number", default_number),
                _required(entry, "ip_address", "FDT entry"),
                _required(entry, "udp_port", "FDT entry"),
                entry.get("ttl"),
                entry.get("remaining_time"),
            )
        )

    if rows:
        connection.executemany(
            """
            INSERT INTO bvlc_fdt_entries (
                packet_id,
                entry_number,
                ip_address,
                udp_port,
                ttl,
                remaining_time
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            rows,
        )


def insert_npdu_header(
    connection: sqlite3.Connection,
    packet_id: int,
    data: LayerRecord,
) -> None:
    """Insert one normalized NPDU header and payload summary."""
    connection.execute(
        """
        INSERT INTO npdu_headers (
            packet_id,
            npdu_version,
            control_byte,
            network_layer_message,
            destination_present,
            source_present,
            expecting_reply,
            priority_code,
            destination_network,
            destination_address_length,
            destination_address,
            destination_address_text,
            destination_is_broadcast,
            destination_is_global_broadcast,
            source_network,
            source_address_length,
            source_address,
            source_address_text,
            hop_count,
            header_length,
            payload_length,
            network_message_type,
            vendor_id,
            network_message_data,
            apdu_parse_valid,
            raw_payload
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            packet_id,
            _required(data, "npdu_version", "NPDU"),
            _required(data, "control_byte", "NPDU"),
            _bool_to_int(_required(data, "network_layer_message", "NPDU")),
            _bool_to_int(_required(data, "destination_present", "NPDU")),
            _bool_to_int(_required(data, "source_present", "NPDU")),
            _bool_to_int(_required(data, "expecting_reply", "NPDU")),
            _required(data, "priority_code", "NPDU"),
            data.get("destination_network"),
            data.get("destination_address_length"),
            _as_blob(data.get("destination_address")),
            data.get("destination_address_text"),
            _bool_to_int(
                _required(data, "destination_is_broadcast", "NPDU")
            ),
            _bool_to_int(
                _required(
                    data,
                    "destination_is_global_broadcast",
                    "NPDU",
                )
            ),
            data.get("source_network"),
            data.get("source_address_length"),
            _as_blob(data.get("source_address")),
            data.get("source_address_text"),
            data.get("hop_count"),
            _required(data, "header_length", "NPDU"),
            _required(data, "payload_length", "NPDU"),
            data.get("network_message_type"),
            data.get("vendor_id"),
            _as_blob(data.get("network_message_data")),
            _bool_to_int(data.get("apdu_parse_valid")),
            _as_blob(_required(data, "raw_payload", "NPDU")),
        ),
    )


def insert_apdu_header(
    connection: sqlite3.Connection,
    packet_id: int,
    data: LayerRecord,
) -> None:
    """Insert one normalized APDU header and raw service payload."""
    connection.execute(
        """
        INSERT INTO apdu_headers (
            packet_id,
            first_byte,
            pdu_type_code,
            flags,
            segmented_message,
            more_follows,
            segmented_response_accepted,
            negative_ack,
            server,
            max_segments_code,
            max_segments_accepted,
            max_apdu_code,
            max_apdu_length,
            invoke_id,
            sequence_number,
            proposed_window_size,
            actual_window_size,
            service_family,
            service_choice,
            error_class,
            error_code,
            reject_reason,
            abort_reason,
            raw_service_data
        )
        VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            packet_id,
            _required(data, "first_byte", "APDU"),
            _required(data, "pdu_type_code", "APDU"),
            _required(data, "flags", "APDU"),
            _bool_to_int(data.get("segmented_message")),
            _bool_to_int(data.get("more_follows")),
            _bool_to_int(data.get("segmented_response_accepted")),
            _bool_to_int(data.get("negative_ack")),
            _bool_to_int(data.get("server")),
            data.get("max_segments_code"),
            data.get("max_segments_accepted"),
            data.get("max_apdu_code"),
            data.get("max_apdu_length"),
            data.get("invoke_id"),
            data.get("sequence_number"),
            data.get("proposed_window_size"),
            data.get("actual_window_size"),
            data.get("service_family"),
            data.get("service_choice"),
            data.get("error_class"),
            data.get("error_code"),
            data.get("reject_reason"),
            data.get("abort_reason"),
            _as_blob(data.get("raw_service_data")),
        ),
    )


def insert_parse_error(
    connection: sqlite3.Connection,
    *,
    packet_id: int,
    parser_stage: str,
    error_message: str,
    error_type: str | None = None,
    byte_offset: int | None = None,
    remaining_data: bytes | bytearray | memoryview | None = None,
) -> int:
    """Insert one parser error and return its ``error_id``."""
    cursor = connection.execute(
        """
        INSERT INTO parse_errors (
            packet_id,
            parser_stage,
            error_type,
            error_message,
            byte_offset,
            remaining_data
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            packet_id,
            parser_stage,
            error_type,
            error_message,
            byte_offset,
            _as_blob(remaining_data),
        ),
    )

    if cursor.lastrowid is None:
        raise sqlite3.DatabaseError(
            "Parse-error insert did not return an error_id"
        )

    return int(cursor.lastrowid)


def insert_parse_errors(
    connection: sqlite3.Connection,
    packet_id: int,
    errors: Iterable[LayerRecord],
) -> None:
    """Insert all parser errors associated with one packet."""
    rows: list[tuple[Any, ...]] = []

    for error in errors:
        rows.append(
            (
                packet_id,
                _required(error, "parser_stage", "parse error"),
                error.get("error_type"),
                _required(error, "error_message", "parse error"),
                error.get("byte_offset"),
                _as_blob(error.get("remaining_data")),
            )
        )

    if rows:
        connection.executemany(
            """
            INSERT INTO parse_errors (
                packet_id,
                parser_stage,
                error_type,
                error_message,
                byte_offset,
                remaining_data
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            rows,
        )


def _resolve_nested_layers(
    packet: PacketRecord,
) -> tuple[
    Mapping[str, Any] | None,
    Mapping[str, Any] | None,
    Mapping[str, Any] | None,
]:
    """Resolve BVLC, NPDU, and APDU records from their natural nesting.

    ``bvlc.py`` stores the NPDU under ``bvlc["npdu"]`` and ``npdu.py`` stores
    the APDU under ``npdu["apdu"]``.  Top-level ``npdu`` and ``apdu`` entries
    remain supported for callers that explicitly flatten those records.
    """
    bvlc = _optional_mapping(packet.get("bvlc"), "BVLC")

    top_level_npdu = _optional_mapping(packet.get("npdu"), "NPDU")
    nested_npdu = None

    if bvlc is not None:
        nested_npdu = _optional_mapping(bvlc.get("npdu"), "nested NPDU")

    npdu = top_level_npdu if top_level_npdu is not None else nested_npdu

    top_level_apdu = _optional_mapping(packet.get("apdu"), "APDU")
    nested_apdu = None

    if npdu is not None:
        nested_apdu = _optional_mapping(npdu.get("apdu"), "nested APDU")

    apdu = top_level_apdu if top_level_apdu is not None else nested_apdu

    return bvlc, npdu, apdu


def insert_parsed_packet(
    connection: sqlite3.Connection,
    *,
    capture_id: int,
    packet: PacketRecord,
) -> int:
    """Insert one parsed packet and every protocol record it contains.

    Expected packet shape::

        {
            "packet_number": 1,
            "timestamp": 1752680000.123,
            "captured_length": 120,
            "original_length": 120,
            "parse_status": "parsed",
            "parse_notes": None,
            "raw_packet": b"...",
            "ethernet": {...},
            "ip": {...},
            "udp": {...},
            "bvlc": {
                ...,
                "bdt_entries": [...],
                "fdt_entries": [...],
                "npdu": {
                    ...,
                    "apdu": {...}
                }
            },
            "parse_errors": [...]
        }

    Top-level ``npdu`` and ``apdu`` records are also accepted.  The entire
    packet insert is atomic: if any layer fails, no row for that packet remains.
    """
    ethernet = _optional_mapping(packet.get("ethernet"), "Ethernet")
    ip = _optional_mapping(packet.get("ip"), "IP")
    udp = _optional_mapping(packet.get("udp"), "UDP")
    bvlc, npdu, apdu = _resolve_nested_layers(packet)

    with _atomic(connection, "packet_insert"):
        packet_id = insert_packet(
            connection,
            capture_id=capture_id,
            packet_number=int(_required(packet, "packet_number", "packet")),
            timestamp=float(_required(packet, "timestamp", "packet")),
            captured_length=packet.get("captured_length"),
            original_length=packet.get("original_length"),
            parse_status=str(packet.get("parse_status", "parsed")),
            parse_notes=packet.get("parse_notes"),
            raw_packet=packet.get("raw_packet"),
        )

        if ethernet is not None:
            insert_ethernet_header(connection, packet_id, ethernet)

        if ip is not None:
            insert_ip_header(connection, packet_id, ip)

        if udp is not None:
            insert_udp_header(connection, packet_id, udp)

        if bvlc is not None:
            insert_bvlc_header(connection, packet_id, bvlc)
            insert_bdt_entries(
                connection,
                packet_id,
                bvlc.get("bdt_entries", ()),
            )
            insert_fdt_entries(
                connection,
                packet_id,
                bvlc.get("fdt_entries", ()),
            )

        if npdu is not None:
            insert_npdu_header(connection, packet_id, npdu)

        if apdu is not None:
            insert_apdu_header(connection, packet_id, apdu)

        insert_parse_errors(
            connection,
            packet_id,
            packet.get("parse_errors", ()),
        )

    return packet_id


def finalize_capture(
    connection: sqlite3.Connection,
    capture_id: int,
) -> None:
    """Recalculate imported packet count and timestamp range."""
    cursor = connection.execute(
        """
        UPDATE captures
        SET
            packet_count = (
                SELECT COUNT(*)
                FROM packets
                WHERE packets.capture_id = captures.capture_id
            ),
            capture_start = (
                SELECT MIN(timestamp)
                FROM packets
                WHERE packets.capture_id = captures.capture_id
            ),
            capture_end = (
                SELECT MAX(timestamp)
                FROM packets
                WHERE packets.capture_id = captures.capture_id
            )
        WHERE capture_id = ?
        """,
        (capture_id,),
    )

    if cursor.rowcount != 1:
        raise ValueError(f"Unknown capture_id: {capture_id}")


def insert_capture_with_packets(
    connection: sqlite3.Connection,
    *,
    filename: str,
    packets: Iterable[PacketRecord],
    file_sha256: str | None = None,
    link_type: int | None = None,
    notes: str | None = None,
) -> int:
    """Insert an entire parsed capture as one atomic transaction."""
    with _atomic(connection, "capture_insert"):
        capture_id = insert_capture(
            connection,
            filename=filename,
            file_sha256=file_sha256,
            link_type=link_type,
            notes=notes,
        )

        for packet in packets:
            insert_parsed_packet(
                connection,
                capture_id=capture_id,
                packet=packet,
            )

        finalize_capture(connection, capture_id)

    return capture_id


def seed_lookup_table(
    connection: sqlite3.Connection,
    *,
    table: str,
    code_column: str,
    name_column: str,
    values: Mapping[int, str],
) -> None:
    """Seed an allowlisted two-column integer-code lookup table."""
    allowed = {
        ("bvlc_types", "type_code", "type_name"),
        ("npdu_priorities", "priority_code", "priority_name"),
        ("npdu_network_messages", "message_type", "message_name"),
        ("apdu_types", "pdu_type_code", "pdu_type_name"),
    }

    identifier_set = (table, code_column, name_column)

    if identifier_set not in allowed:
        raise ValueError(
            f"Unsupported lookup table definition: {identifier_set}"
        )

    connection.executemany(
        f"""
        INSERT INTO {table} ({code_column}, {name_column})
        VALUES (?, ?)
        ON CONFLICT({code_column}) DO UPDATE SET
            {name_column} = excluded.{name_column}
        """,
        values.items(),
    )


def seed_bvlc_functions(
    connection: sqlite3.Connection,
    values: Mapping[tuple[int, int], str],
) -> None:
    """Seed BVLC function names keyed by type and function code."""
    connection.executemany(
        """
        INSERT INTO bvlc_functions (
            type_code,
            function_code,
            function_name
        )
        VALUES (?, ?, ?)
        ON CONFLICT(type_code, function_code) DO UPDATE SET
            function_name = excluded.function_name
        """,
        (
            (type_code, function_code, function_name)
            for (type_code, function_code), function_name in values.items()
        ),
    )


def seed_bvlc_result_codes(
    connection: sqlite3.Connection,
    values: Mapping[tuple[int, int], str],
) -> None:
    """Seed BVLC result names keyed by type and result code."""
    connection.executemany(
        """
        INSERT INTO bvlc_result_codes (
            type_code,
            result_code,
            result_name
        )
        VALUES (?, ?, ?)
        ON CONFLICT(type_code, result_code) DO UPDATE SET
            result_name = excluded.result_name
        """,
        (
            (type_code, result_code, result_name)
            for (type_code, result_code), result_name in values.items()
        ),
    )


def seed_bacnet_services(
    connection: sqlite3.Connection,
    *,
    confirmed_services: Mapping[int, str],
    unconfirmed_services: Mapping[int, str],
) -> None:
    """Seed confirmed and unconfirmed BACnet service names."""
    rows = [
        ("confirmed", code, name)
        for code, name in confirmed_services.items()
    ]
    rows.extend(
        ("unconfirmed", code, name)
        for code, name in unconfirmed_services.items()
    )

    connection.executemany(
        """
        INSERT INTO bacnet_services (
            service_family,
            service_code,
            service_name
        )
        VALUES (?, ?, ?)
        ON CONFLICT(service_family, service_code) DO UPDATE SET
            service_name = excluded.service_name
        """,
        rows,
    )


def seed_all_lookups(
    connection: sqlite3.Connection,
    *,
    bvlc_types: Mapping[int, str],
    bvlc_functions: Mapping[tuple[int, int], str],
    bvlc_result_codes: Mapping[tuple[int, int], str],
    npdu_priorities: Mapping[int, str],
    npdu_network_messages: Mapping[int, str],
    apdu_types: Mapping[int, str],
    confirmed_services: Mapping[int, str],
    unconfirmed_services: Mapping[int, str],
) -> None:
    """Seed every protocol lookup table atomically."""
    with _atomic(connection, "lookup_seed"):
        seed_lookup_table(
            connection,
            table="bvlc_types",
            code_column="type_code",
            name_column="type_name",
            values=bvlc_types,
        )
        seed_bvlc_functions(connection, bvlc_functions)
        seed_bvlc_result_codes(connection, bvlc_result_codes)
        seed_lookup_table(
            connection,
            table="npdu_priorities",
            code_column="priority_code",
            name_column="priority_name",
            values=npdu_priorities,
        )
        seed_lookup_table(
            connection,
            table="npdu_network_messages",
            code_column="message_type",
            name_column="message_name",
            values=npdu_network_messages,
        )
        seed_lookup_table(
            connection,
            table="apdu_types",
            code_column="pdu_type_code",
            name_column="pdu_type_name",
            values=apdu_types,
        )
        seed_bacnet_services(
            connection,
            confirmed_services=confirmed_services,
            unconfirmed_services=unconfirmed_services,
        )


def seed_default_lookups(connection: sqlite3.Connection) -> None:
    """Seed lookup tables from this project's ``constants.py`` values."""
    seed_all_lookups(
        connection,
        bvlc_types=BVLC_TYPES,
        bvlc_functions=BVLC_FUNCTIONS,
        bvlc_result_codes=BVLC_RESULT_CODES,
        npdu_priorities=NPDU_PRIORITIES,
        npdu_network_messages=NPDU_NETWORK_MESSAGES,
        apdu_types=APDU_TYPES,
        confirmed_services=CONFIRMED_SERVICES,
        unconfirmed_services=UNCONFIRMED_SERVICES,
    )

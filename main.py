"""Command-line PCAP importer for the BACnet analysis project.

This module connects the capture metadata reader, Scapy packet processing,
BACnet protocol parsers, and SQLite insertion layer. Importing a capture is
transactional: either the capture and all of its packets are stored, or no part
of that capture import remains in the database.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from collections import Counter
from collections.abc import Iterator, Sequence
from pathlib import Path
from pprint import pprint
from typing import Any

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import PcapReader

from bacnet_database_inserts import (
    finalize_capture,
    insert_capture_metadata,
    insert_parsed_packet,
    seed_default_lookups,
)
from capture import get_capture_metadata
from constants import BVLC_TYPES
from database import (
    DEFAULT_DATABASE_PATH,
    DatabaseSchemaError,
    initialize_database,
)
from layers import (
    process_ether_layer,
    process_ip_layer,
    process_udp_layer,
    process_udp_payload,
)


PacketRecord = dict[str, Any]
ImportSummary = dict[str, Any]


class DuplicateCaptureError(ValueError):
    """Raised when the same capture file has already been imported."""


def _packet_bytes(packet: Packet) -> bytes:
    """Serialize one Scapy packet for storage in the database."""
    return bytes(packet)


def _original_packet_length(packet: Packet, captured_length: int) -> int:
    """Return the on-wire length when Scapy provides it."""
    wire_length = getattr(packet, "wirelen", None)

    if wire_length is None:
        return captured_length

    try:
        return int(wire_length)
    except (TypeError, ValueError):
        return captured_length


def _parse_error(
    parser_stage: str,
    error_message: str,
    *,
    error_type: str | None = None,
    byte_offset: int | None = None,
    remaining_data: bytes | None = None,
) -> dict[str, Any]:
    """Build one normalized parse-error record."""
    return {
        "parser_stage": parser_stage,
        "error_type": error_type,
        "error_message": error_message,
        "byte_offset": byte_offset,
        "remaining_data": remaining_data,
    }


def _record_exception(
    packet_data: PacketRecord,
    parser_stage: str,
    error: Exception,
    *,
    remaining_data: bytes | None = None,
) -> None:
    """Attach a caught parser exception without losing the packet."""
    packet_data["parse_errors"].append(
        _parse_error(
            parser_stage,
            str(error) or error.__class__.__name__,
            error_type=error.__class__.__name__,
            remaining_data=remaining_data,
        )
    )


def _evaluate_bvlc_result(
    packet_data: PacketRecord,
    bvlc_data: dict[str, Any],
) -> tuple[bool, bool, bool]:
    """Collect BVLC/APDU issues and return status flags.

    Returns:
        ``(malformed, partial, unsupported)``.
    """
    malformed = False
    partial = False
    unsupported = False

    body_error = bvlc_data.get("body_parse_error")
    if body_error:
        malformed = True
        packet_data["parse_errors"].append(
            _parse_error(
                "bvlc",
                str(body_error),
                error_type="MalformedBVLC",
                remaining_data=bvlc_data.get("raw_body"),
            )
        )

    if bvlc_data.get("length_valid") is False and not body_error:
        malformed = True
        packet_data["parse_errors"].append(
            _parse_error(
                "bvlc",
                "BVLC declared length does not match the captured payload",
                error_type="InvalidBVLCLength",
                remaining_data=bvlc_data.get("raw_body"),
            )
        )

    unsupported_reason = bvlc_data.get("unsupported_reason")
    if unsupported_reason:
        unsupported = True
        packet_data["parse_errors"].append(
            _parse_error(
                "bvlc",
                str(unsupported_reason),
                error_type="UnsupportedBVLC",
                remaining_data=bvlc_data.get("raw_body"),
            )
        )

    npdu_data = bvlc_data.get("npdu")
    if isinstance(npdu_data, dict) and npdu_data.get("apdu_parse_valid") is False:
        partial = True
        packet_data["parse_errors"].append(
            _parse_error(
                "apdu",
                "NPDU payload contains a malformed or unsupported APDU",
                error_type="MalformedAPDU",
                remaining_data=npdu_data.get("raw_payload"),
            )
        )

    return malformed, partial, unsupported


def process_packet(packet: Packet, packet_number: int) -> PacketRecord:
    """Normalize one Scapy packet for database insertion.

    Every packet is preserved, including non-BACnet traffic and packets whose
    protocol parsing fails. Parser failures become rows in ``parse_errors``
    rather than terminating the entire capture import.
    """
    raw_packet = _packet_bytes(packet)
    captured_length = len(raw_packet)

    packet_data: PacketRecord = {
        "packet_number": packet_number,
        "timestamp": float(packet.time),
        "captured_length": captured_length,
        "original_length": _original_packet_length(
            packet,
            captured_length,
        ),
        "parse_status": "unsupported",
        "parse_notes": None,
        "raw_packet": raw_packet,
        "ethernet": None,
        "ip": None,
        "udp": None,
        "bvlc": None,
        "parse_errors": [],
    }

    parser_exception = False
    malformed = False
    partial = False
    unsupported = False
    recognized_bacnet = False

    if packet.haslayer(Ether):
        try:
            packet_data["ethernet"] = process_ether_layer(packet[Ether])
        except Exception as error:
            parser_exception = True
            _record_exception(packet_data, "ethernet", error)

    if packet.haslayer(IP):
        try:
            packet_data["ip"] = process_ip_layer(packet[IP])
        except Exception as error:
            parser_exception = True
            _record_exception(packet_data, "ip", error)

    if packet.haslayer(UDP):
        udp_layer = packet[UDP]

        try:
            packet_data["udp"] = process_udp_layer(udp_layer)
        except Exception as error:
            parser_exception = True
            _record_exception(packet_data, "udp", error)

        udp_payload = bytes(udp_layer.payload)

        if udp_payload and udp_payload[0] in BVLC_TYPES:
            recognized_bacnet = True

            try:
                bvlc_data = process_udp_payload(udp_layer)
            except Exception as error:
                parser_exception = True
                _record_exception(
                    packet_data,
                    "bvlc",
                    error,
                    remaining_data=udp_payload,
                )
            else:
                if bvlc_data is None:
                    malformed = True
                    packet_data["parse_errors"].append(
                        _parse_error(
                            "bvlc",
                            "Payload begins with a known BVLC type but does not contain a complete BVLC header",
                            error_type="TruncatedBVLC",
                            remaining_data=udp_payload,
                        )
                    )
                else:
                    packet_data["bvlc"] = bvlc_data
                    (
                        bvlc_malformed,
                        bvlc_partial,
                        bvlc_unsupported,
                    ) = _evaluate_bvlc_result(packet_data, bvlc_data)
                    malformed = malformed or bvlc_malformed
                    partial = partial or bvlc_partial
                    unsupported = unsupported or bvlc_unsupported
        else:
            unsupported = True
    else:
        unsupported = True

    if parser_exception:
        packet_data["parse_status"] = "error"
        packet_data["parse_notes"] = "One or more parser stages raised an exception"
    elif malformed:
        packet_data["parse_status"] = "malformed"
        packet_data["parse_notes"] = "BACnet traffic was recognized but contains malformed protocol data"
    elif partial:
        packet_data["parse_status"] = "partial"
        packet_data["parse_notes"] = "BACnet headers were parsed, but a nested protocol payload was not"
    elif recognized_bacnet and not unsupported:
        packet_data["parse_status"] = "parsed"
    else:
        packet_data["parse_status"] = "unsupported"
        packet_data["parse_notes"] = (
            "Packet does not contain a fully supported BACnet BVLC payload"
        )

    return packet_data


def iter_parsed_packets(filename: str | Path) -> Iterator[PacketRecord]:
    """Yield normalized packet records from a PCAP or PCAPNG file."""
    path = Path(filename)

    with PcapReader(str(path)) as capture_reader:
        for packet_number, packet in enumerate(capture_reader, start=1):
            yield process_packet(packet, packet_number)


def _display_packet(packet_data: PacketRecord) -> None:
    """Print a readable packet record without dumping the full raw frame."""
    display_record = dict(packet_data)
    raw_packet = display_record.get("raw_packet")

    if isinstance(raw_packet, bytes):
        display_record["raw_packet"] = f"<{len(raw_packet)} bytes>"

    pprint(display_record, sort_dicts=False)


def _existing_capture(
    connection: sqlite3.Connection,
    file_sha256: str,
) -> sqlite3.Row | None:
    """Find an already imported capture by its content hash."""
    return connection.execute(
        """
        SELECT capture_id, filename
        FROM captures
        WHERE file_sha256 = ?
        """,
        (file_sha256,),
    ).fetchone()


def import_capture(
    connection: sqlite3.Connection,
    filename: str | Path,
    *,
    notes: str | None = None,
    replace_existing: bool = False,
    print_packets: bool = False,
) -> ImportSummary:
    """Import one capture and all parsed packets as a single transaction."""
    metadata = get_capture_metadata(filename)
    file_sha256 = str(metadata["file_sha256"])
    status_counts: Counter[str] = Counter()

    with connection:
        existing = _existing_capture(connection, file_sha256)

        if existing is not None:
            if not replace_existing:
                raise DuplicateCaptureError(
                    "Capture has already been imported as "
                    f"capture_id {existing['capture_id']} "
                    f"from {existing['filename']!r}"
                )

            connection.execute(
                "DELETE FROM captures WHERE capture_id = ?",
                (int(existing["capture_id"]),),
            )

        capture_id = insert_capture_metadata(
            connection,
            metadata,
            notes=notes,
        )

        for packet_data in iter_parsed_packets(filename):
            insert_parsed_packet(
                connection,
                capture_id=capture_id,
                packet=packet_data,
            )
            status_counts[str(packet_data["parse_status"])] += 1

            if print_packets:
                _display_packet(packet_data)

        finalize_capture(connection, capture_id)

    imported_row = connection.execute(
        """
        SELECT packet_count, capture_start, capture_end
        FROM captures
        WHERE capture_id = ?
        """,
        (capture_id,),
    ).fetchone()

    if imported_row is None:
        raise sqlite3.DatabaseError(
            "Imported capture row disappeared after commit"
        )

    return {
        "capture_id": capture_id,
        "filename": str(metadata["filename"]),
        "file_sha256": file_sha256,
        "packet_count": int(imported_row["packet_count"] or 0),
        "capture_start": imported_row["capture_start"],
        "capture_end": imported_row["capture_end"],
        "status_counts": dict(status_counts),
    }


def _build_argument_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Parse a PCAP/PCAPNG capture and import BACnet packet data "
            "into SQLite."
        )
    )
    parser.add_argument(
        "capture",
        type=Path,
        help="Path to the PCAP or PCAPNG file",
    )
    parser.add_argument(
        "-d",
        "--database",
        type=Path,
        default=Path(DEFAULT_DATABASE_PATH),
        help=f"SQLite database path (default: {DEFAULT_DATABASE_PATH})",
    )
    parser.add_argument(
        "--notes",
        help="Optional notes stored with the capture",
    )
    parser.add_argument(
        "--replace-existing",
        action="store_true",
        help="Replace a previously imported capture with the same SHA-256",
    )
    parser.add_argument(
        "--print-packets",
        action="store_true",
        help="Print each normalized packet while importing",
    )
    return parser


def _print_summary(summary: ImportSummary, database_path: Path) -> None:
    """Print a concise import result."""
    print(f"Imported capture ID: {summary['capture_id']}")
    print(f"Capture: {summary['filename']}")
    print(f"Database: {database_path}")
    print(f"Packets: {summary['packet_count']}")

    status_counts = summary.get("status_counts", {})
    if status_counts:
        ordered_statuses = (
            "parsed",
            "partial",
            "unsupported",
            "malformed",
            "error",
        )
        status_text = ", ".join(
            f"{status}={status_counts.get(status, 0)}"
            for status in ordered_statuses
        )
        print(f"Statuses: {status_text}")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line importer and return a process exit code."""
    arguments = _build_argument_parser().parse_args(argv)
    connection: sqlite3.Connection | None = None

    try:
        connection = initialize_database(arguments.database)
        seed_default_lookups(connection)

        summary = import_capture(
            connection,
            arguments.capture,
            notes=arguments.notes,
            replace_existing=arguments.replace_existing,
            print_packets=arguments.print_packets,
        )

    except (
        DatabaseSchemaError,
        DuplicateCaptureError,
        FileNotFoundError,
        OSError,
        sqlite3.Error,
        ValueError,
    ) as error:
        print(f"Import failed: {error}", file=sys.stderr)
        return 1

    finally:
        if connection is not None:
            connection.close()

    _print_summary(summary, arguments.database)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
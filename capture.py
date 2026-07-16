"""Collect file-level metadata from PCAP and PCAPNG captures.

This module deliberately uses Scapy's raw capture reader. File metadata does
not require protocol dissection, and reading raw records keeps the operation
fast and tolerant of unknown or malformed packet payloads.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from scapy.utils import RawPcapReader


CaptureMetadata = dict[str, Any]

_HASH_CHUNK_SIZE = 1024 * 1024


def calculate_file_sha256(
    filename: str | Path,
    *,
    chunk_size: int = _HASH_CHUNK_SIZE,
) -> str:
    """Calculate the SHA-256 digest without loading the whole file at once."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    path = Path(filename)

    if not path.is_file():
        raise FileNotFoundError(
            f"Capture file does not exist: {path}"
        )

    digest = hashlib.sha256()

    with path.open("rb") as capture_file:
        for chunk in iter(
            lambda: capture_file.read(chunk_size),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def _packet_timestamp(
    reader: Any,
    metadata: Any,
) -> float | None:
    """Convert Scapy PCAP or PCAPNG metadata to Unix time."""

    # Classic PCAP metadata contains seconds and either a
    # microsecond or nanosecond fractional field.
    if hasattr(metadata, "sec") and hasattr(metadata, "usec"):
        divisor = (
            1_000_000_000
            if getattr(reader, "nano", False)
            else 1_000_000
        )

        return float(metadata.sec) + (
            float(metadata.usec) / divisor
        )

    # PCAPNG stores the timestamp as one 64-bit value split
    # into high and low portions.
    timestamp_high = getattr(metadata, "tshigh", None)
    timestamp_low = getattr(metadata, "tslow", None)
    timestamp_resolution = getattr(
        metadata,
        "tsresol",
        None,
    )

    if (
        timestamp_high is None
        or timestamp_low is None
        or timestamp_resolution in (None, 0)
    ):
        return None

    timestamp_value = (
        int(timestamp_high) << 32
    ) | int(timestamp_low)

    return timestamp_value / float(timestamp_resolution)


def get_capture_metadata(
    filename: str | Path,
) -> CaptureMetadata:
    """Read capture metadata needed by the database importer.

    Returns:
        A dictionary containing:

        filename:
            The supplied capture path as a string.

        file_sha256:
            SHA-256 digest of the complete capture file.

        capture_start:
            Earliest packet timestamp, or None for an empty
            capture.

        capture_end:
            Latest packet timestamp, or None for an empty
            capture.

        packet_count:
            Number of packet records in the capture.

        link_type:
            The capture link-layer type when exactly one type
            is present. This is None for mixed-link-type
            PCAPNG captures.

        link_types:
            Every observed link-layer type in sorted order.
    """
    path = Path(filename)

    if not path.is_file():
        raise FileNotFoundError(
            f"Capture file does not exist: {path}"
        )

    packet_count = 0
    capture_start: float | None = None
    capture_end: float | None = None
    link_types: set[int] = set()

    reader = RawPcapReader(str(path))

    try:
        # Classic PCAP stores one file-wide link type.
        reader_link_type = getattr(
            reader,
            "linktype",
            None,
        )

        if reader_link_type is not None:
            link_types.add(int(reader_link_type))

        for _, packet_metadata in reader:
            packet_count += 1

            # PCAPNG can use separate link types for different
            # interfaces in the same capture.
            packet_link_type = getattr(
                packet_metadata,
                "linktype",
                None,
            )

            if packet_link_type is not None:
                link_types.add(int(packet_link_type))

            timestamp = _packet_timestamp(
                reader,
                packet_metadata,
            )

            if timestamp is None:
                continue

            if (
                capture_start is None
                or timestamp < capture_start
            ):
                capture_start = timestamp

            if (
                capture_end is None
                or timestamp > capture_end
            ):
                capture_end = timestamp

    finally:
        reader.close()

    sorted_link_types = sorted(link_types)

    link_type = (
        sorted_link_types[0]
        if len(sorted_link_types) == 1
        else None
    )

    return {
        "filename": str(path),
        "file_sha256": calculate_file_sha256(path),
        "capture_start": capture_start,
        "capture_end": capture_end,
        "packet_count": packet_count,
        "link_type": link_type,
        "link_types": sorted_link_types,
    }
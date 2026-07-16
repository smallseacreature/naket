"""Compatibility wrapper for parsed-packet database insertion.

The canonical insertion implementation lives in
``bacnet_database_inserts.py``. This module preserves the simpler positional
API used by earlier versions of the project without maintaining a second copy
of the insertion logic.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import Any

from bacnet_database_inserts import (
    insert_parsed_packet as _insert_parsed_packet,
)


PacketRecord = Mapping[str, Any]

__all__ = ["insert_parsed_packet"]


def insert_parsed_packet(
    connection: sqlite3.Connection,
    capture_id: int,
    packet_data: PacketRecord,
) -> int:
    """Insert one parsed packet and return its database ``packet_id``.

    This function delegates to
    :func:`bacnet_database_inserts.insert_parsed_packet`, which is the single
    source of truth for packet, layer, child-entry, and parse-error insertion.

    Args:
        connection: Open SQLite connection initialized by ``database.py``.
        capture_id: Parent capture row identifier.
        packet_data: Normalized packet dictionary produced by ``main.py``.

    Returns:
        The newly created packet row identifier.
    """
    return _insert_parsed_packet(
        connection,
        capture_id=capture_id,
        packet=packet_data,
    )
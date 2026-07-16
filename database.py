"""SQLite database initialization for the BACnet capture project.

This module owns the database connection settings and schema only. Packet and
lookup-table insertion functions live in ``bacnet_database_inserts.py``.

The schema intentionally does not foreign-key observed protocol codes to lookup
tables. BACnet captures can contain reserved, vendor-proprietary, malformed, or
future codes, and those packets must remain insertable for forensic analysis.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Final


DEFAULT_DATABASE_PATH: Final[str] = "bacnet.db"
SCHEMA_VERSION: Final[int] = 1


class DatabaseSchemaError(RuntimeError):
    """Raised when an existing database does not match this project schema."""


SCHEMA_SQL: Final[str] = """
CREATE TABLE IF NOT EXISTS captures (
    capture_id INTEGER PRIMARY KEY,
    filename TEXT NOT NULL,
    file_sha256 TEXT UNIQUE,
    imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    capture_start REAL,
    capture_end REAL,
    packet_count INTEGER
        CHECK (packet_count IS NULL OR packet_count >= 0),
    link_type INTEGER,
    notes TEXT,

    CHECK (
        capture_start IS NULL
        OR capture_end IS NULL
        OR capture_end >= capture_start
    )
);

CREATE TABLE IF NOT EXISTS packets (
    packet_id INTEGER PRIMARY KEY,
    capture_id INTEGER NOT NULL,
    packet_number INTEGER NOT NULL
        CHECK (packet_number >= 1),
    timestamp REAL NOT NULL,
    captured_length INTEGER
        CHECK (captured_length IS NULL OR captured_length >= 0),
    original_length INTEGER
        CHECK (original_length IS NULL OR original_length >= 0),
    parse_status TEXT NOT NULL DEFAULT 'parsed'
        CHECK (
            parse_status IN (
                'parsed',
                'partial',
                'unsupported',
                'malformed',
                'error'
            )
        ),
    parse_notes TEXT,
    raw_packet BLOB,

    FOREIGN KEY (capture_id)
        REFERENCES captures(capture_id)
        ON DELETE CASCADE,

    UNIQUE (capture_id, packet_number)
);

CREATE TABLE IF NOT EXISTS ethernet_headers (
    packet_id INTEGER PRIMARY KEY,
    source_mac TEXT NOT NULL,
    destination_mac TEXT NOT NULL,
    ether_type INTEGER,

    FOREIGN KEY (packet_id)
        REFERENCES packets(packet_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ip_headers (
    packet_id INTEGER PRIMARY KEY,
    ip_version INTEGER NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    protocol INTEGER,
    ttl INTEGER,
    identification INTEGER,
    flags INTEGER,
    fragment_offset INTEGER,
    header_length INTEGER,
    total_length INTEGER,
    checksum INTEGER,

    FOREIGN KEY (packet_id)
        REFERENCES packets(packet_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS udp_headers (
    packet_id INTEGER PRIMARY KEY,
    source_port INTEGER NOT NULL
        CHECK (source_port BETWEEN 0 AND 65535),
    destination_port INTEGER NOT NULL
        CHECK (destination_port BETWEEN 0 AND 65535),
    udp_length INTEGER,
    checksum INTEGER,

    FOREIGN KEY (packet_id)
        REFERENCES packets(packet_id)
        ON DELETE CASCADE
);

-- Lookup tables used by reports and the future interface.

CREATE TABLE IF NOT EXISTS bvlc_types (
    type_code INTEGER PRIMARY KEY,
    type_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bvlc_functions (
    type_code INTEGER NOT NULL,
    function_code INTEGER NOT NULL,
    function_name TEXT NOT NULL,

    PRIMARY KEY (type_code, function_code)
);

CREATE TABLE IF NOT EXISTS bvlc_result_codes (
    type_code INTEGER NOT NULL,
    result_code INTEGER NOT NULL,
    result_name TEXT NOT NULL,

    PRIMARY KEY (type_code, result_code)
);

CREATE TABLE IF NOT EXISTS npdu_priorities (
    priority_code INTEGER PRIMARY KEY,
    priority_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS npdu_network_messages (
    message_type INTEGER PRIMARY KEY,
    message_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS apdu_types (
    pdu_type_code INTEGER PRIMARY KEY,
    pdu_type_name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bacnet_services (
    service_family TEXT NOT NULL
        CHECK (
            service_family IN (
                'confirmed',
                'unconfirmed'
            )
        ),
    service_code INTEGER NOT NULL,
    service_name TEXT NOT NULL,

    PRIMARY KEY (service_family, service_code)
);

CREATE TABLE IF NOT EXISTS bvlc_headers (
    packet_id INTEGER PRIMARY KEY,
    bvlc_type_code INTEGER NOT NULL,
    function_code INTEGER NOT NULL,
    declared_length INTEGER,
    actual_length INTEGER,

    length_valid INTEGER
        CHECK (
            length_valid IS NULL
            OR length_valid IN (0, 1)
        ),

    body_parse_valid INTEGER
        CHECK (
            body_parse_valid IS NULL
            OR body_parse_valid IN (0, 1)
        ),

    parse_valid INTEGER NOT NULL DEFAULT 0
        CHECK (parse_valid IN (0, 1)),

    body_parse_error TEXT,
    result_code INTEGER,
    originating_ip TEXT,
    originating_port INTEGER,
    registration_ttl INTEGER,
    delete_ip TEXT,
    delete_port INTEGER,
    security_control INTEGER,
    security_wrapper_data BLOB,
    security_signature BLOB,
    raw_body BLOB,
    trailing_data BLOB,
    unsupported_reason TEXT,

    FOREIGN KEY (packet_id)
        REFERENCES packets(packet_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bvlc_bdt_entries (
    bdt_entry_id INTEGER PRIMARY KEY,
    packet_id INTEGER NOT NULL,
    entry_number INTEGER NOT NULL
        CHECK (entry_number >= 0),
    ip_address TEXT NOT NULL,
    udp_port INTEGER NOT NULL
        CHECK (udp_port BETWEEN 0 AND 65535),
    broadcast_mask TEXT,

    FOREIGN KEY (packet_id)
        REFERENCES packets(packet_id)
        ON DELETE CASCADE,

    UNIQUE (packet_id, entry_number)
);

CREATE TABLE IF NOT EXISTS bvlc_fdt_entries (
    fdt_entry_id INTEGER PRIMARY KEY,
    packet_id INTEGER NOT NULL,
    entry_number INTEGER NOT NULL
        CHECK (entry_number >= 0),
    ip_address TEXT NOT NULL,
    udp_port INTEGER NOT NULL
        CHECK (udp_port BETWEEN 0 AND 65535),
    ttl INTEGER,
    remaining_time INTEGER,

    FOREIGN KEY (packet_id)
        REFERENCES packets(packet_id)
        ON DELETE CASCADE,

    UNIQUE (packet_id, entry_number)
);

CREATE TABLE IF NOT EXISTS npdu_headers (
    packet_id INTEGER PRIMARY KEY,
    npdu_version INTEGER NOT NULL,
    control_byte INTEGER NOT NULL,

    network_layer_message INTEGER NOT NULL DEFAULT 0
        CHECK (network_layer_message IN (0, 1)),

    destination_present INTEGER NOT NULL DEFAULT 0
        CHECK (destination_present IN (0, 1)),

    source_present INTEGER NOT NULL DEFAULT 0
        CHECK (source_present IN (0, 1)),

    expecting_reply INTEGER NOT NULL DEFAULT 0
        CHECK (expecting_reply IN (0, 1)),

    priority_code INTEGER NOT NULL,
    destination_network INTEGER,
    destination_address_length INTEGER,
    destination_address BLOB,
    destination_address_text TEXT,

    destination_is_broadcast INTEGER NOT NULL DEFAULT 0
        CHECK (destination_is_broadcast IN (0, 1)),

    destination_is_global_broadcast INTEGER NOT NULL DEFAULT 0
        CHECK (
            destination_is_global_broadcast IN (0, 1)
        ),

    source_network INTEGER,
    source_address_length INTEGER,
    source_address BLOB,
    source_address_text TEXT,
    hop_count INTEGER,
    header_length INTEGER NOT NULL,
    payload_length INTEGER NOT NULL,
    network_message_type INTEGER,
    vendor_id INTEGER,
    network_message_data BLOB,

    apdu_parse_valid INTEGER
        CHECK (
            apdu_parse_valid IS NULL
            OR apdu_parse_valid IN (0, 1)
        ),

    raw_payload BLOB NOT NULL,

    FOREIGN KEY (packet_id)
        REFERENCES packets(packet_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS apdu_headers (
    packet_id INTEGER PRIMARY KEY,
    first_byte INTEGER NOT NULL,
    pdu_type_code INTEGER NOT NULL,
    flags INTEGER NOT NULL,

    segmented_message INTEGER
        CHECK (
            segmented_message IS NULL
            OR segmented_message IN (0, 1)
        ),

    more_follows INTEGER
        CHECK (
            more_follows IS NULL
            OR more_follows IN (0, 1)
        ),

    segmented_response_accepted INTEGER
        CHECK (
            segmented_response_accepted IS NULL
            OR segmented_response_accepted IN (0, 1)
        ),

    negative_ack INTEGER
        CHECK (
            negative_ack IS NULL
            OR negative_ack IN (0, 1)
        ),

    server INTEGER
        CHECK (
            server IS NULL
            OR server IN (0, 1)
        ),

    max_segments_code INTEGER,
    max_segments_accepted TEXT,
    max_apdu_code INTEGER,
    max_apdu_length INTEGER,
    invoke_id INTEGER,
    sequence_number INTEGER,
    proposed_window_size INTEGER,
    actual_window_size INTEGER,

    service_family TEXT
        CHECK (
            service_family IS NULL
            OR service_family IN (
                'confirmed',
                'unconfirmed'
            )
        ),

    service_choice INTEGER,
    error_class INTEGER,
    error_code INTEGER,
    reject_reason INTEGER,
    abort_reason INTEGER,
    raw_service_data BLOB,

    FOREIGN KEY (packet_id)
        REFERENCES packets(packet_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS parse_errors (
    error_id INTEGER PRIMARY KEY,
    packet_id INTEGER NOT NULL,
    parser_stage TEXT NOT NULL,
    error_type TEXT,
    error_message TEXT NOT NULL,
    byte_offset INTEGER,
    remaining_data BLOB,

    FOREIGN KEY (packet_id)
        REFERENCES packets(packet_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_captures_imported_at
    ON captures(imported_at);

CREATE INDEX IF NOT EXISTS idx_packets_capture_timestamp
    ON packets(capture_id, timestamp);

CREATE INDEX IF NOT EXISTS idx_packets_parse_status
    ON packets(parse_status);

CREATE INDEX IF NOT EXISTS idx_ip_source
    ON ip_headers(source_ip);

CREATE INDEX IF NOT EXISTS idx_ip_destination
    ON ip_headers(destination_ip);

CREATE INDEX IF NOT EXISTS idx_ip_pair
    ON ip_headers(
        source_ip,
        destination_ip
    );

CREATE INDEX IF NOT EXISTS idx_udp_source_port
    ON udp_headers(source_port);

CREATE INDEX IF NOT EXISTS idx_udp_destination_port
    ON udp_headers(destination_port);

CREATE INDEX IF NOT EXISTS idx_bvlc_function
    ON bvlc_headers(
        bvlc_type_code,
        function_code
    );

CREATE INDEX IF NOT EXISTS idx_bvlc_result
    ON bvlc_headers(
        bvlc_type_code,
        result_code
    );

CREATE INDEX IF NOT EXISTS idx_npdu_priority
    ON npdu_headers(priority_code);

CREATE INDEX IF NOT EXISTS idx_npdu_network_message
    ON npdu_headers(network_message_type);

CREATE INDEX IF NOT EXISTS idx_apdu_type
    ON apdu_headers(pdu_type_code);

CREATE INDEX IF NOT EXISTS idx_apdu_service
    ON apdu_headers(
        service_family,
        service_choice
    );

CREATE INDEX IF NOT EXISTS idx_apdu_invoke_id
    ON apdu_headers(invoke_id);

CREATE INDEX IF NOT EXISTS idx_parse_errors_stage
    ON parse_errors(parser_stage);
"""


REQUIRED_COLUMNS: Final[dict[str, set[str]]] = {
    "captures": {
        "capture_id",
        "filename",
        "file_sha256",
        "capture_start",
        "capture_end",
        "packet_count",
        "link_type",
    },
    "packets": {
        "packet_id",
        "capture_id",
        "packet_number",
        "timestamp",
        "parse_status",
        "raw_packet",
    },
    "bvlc_headers": {
        "packet_id",
        "bvlc_type_code",
        "function_code",
        "body_parse_valid",
        "parse_valid",
        "security_wrapper_data",
        "trailing_data",
    },
    "npdu_headers": {
        "packet_id",
        "control_byte",
        "destination_address_length",
        "destination_is_broadcast",
        "source_address_length",
        "network_message_data",
        "apdu_parse_valid",
    },
    "apdu_headers": {
        "packet_id",
        "first_byte",
        "max_segments_accepted",
        "actual_window_size",
        "raw_service_data",
    },
}


def _configure_connection(
    connection: sqlite3.Connection,
) -> None:
    """Apply settings required by every project database handle."""
    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    connection.execute(
        "PRAGMA busy_timeout = 5000"
    )

    # WAL improves concurrent importer/UI access for
    # file-backed databases. SQLite may return another mode
    # for special databases such as :memory:.
    connection.execute(
        "PRAGMA journal_mode = WAL"
    )

    connection.execute(
        "PRAGMA synchronous = NORMAL"
    )


def _user_tables(
    connection: sqlite3.Connection,
) -> set[str]:
    """Return application tables, excluding SQLite internal tables."""
    rows = connection.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name NOT LIKE 'sqlite_%'
        """
    )

    return {
        str(row[0])
        for row in rows
    }


def _table_columns(
    connection: sqlite3.Connection,
    table_name: str,
) -> set[str]:
    """Return every column name for one trusted project table."""
    rows = connection.execute(
        f'PRAGMA table_info("{table_name}")'
    )

    return {
        str(row[1])
        for row in rows
    }


def validate_database_schema(
    connection: sqlite3.Connection,
) -> None:
    """Verify schema version, required columns, and foreign keys."""
    version = int(
        connection.execute(
            "PRAGMA user_version"
        ).fetchone()[0]
    )

    if version != SCHEMA_VERSION:
        raise DatabaseSchemaError(
            f"Database schema version is {version}; "
            f"expected {SCHEMA_VERSION}."
        )

    existing_tables = _user_tables(connection)
    missing_tables = (
        set(REQUIRED_COLUMNS)
        - existing_tables
    )

    if missing_tables:
        names = ", ".join(
            sorted(missing_tables)
        )

        raise DatabaseSchemaError(
            f"Database is missing required tables: {names}"
        )

    for table_name, required_columns in REQUIRED_COLUMNS.items():
        existing_columns = _table_columns(
            connection,
            table_name,
        )

        missing_columns = (
            required_columns
            - existing_columns
        )

        if missing_columns:
            names = ", ".join(
                sorted(missing_columns)
            )

            raise DatabaseSchemaError(
                f"Table {table_name!r} is missing "
                f"columns: {names}"
            )

    violations = connection.execute(
        "PRAGMA foreign_key_check"
    ).fetchall()

    if violations:
        raise DatabaseSchemaError(
            f"Database contains {len(violations)} "
            "foreign-key violation(s)."
        )


def initialize_database(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> sqlite3.Connection:
    """Create or open the BACnet database.

    The returned connection remains open. The caller owns it
    and must close it when database work is finished.

    If initialization fails, this function closes the
    connection before re-raising the original exception.

    Existing pre-versioned databases are rejected instead of
    being silently used with an incompatible schema.
    """
    connection = sqlite3.connect(
        str(database_path),
        timeout=30.0,
    )

    try:
        _configure_connection(connection)

        existing_tables = _user_tables(connection)

        current_version = int(
            connection.execute(
                "PRAGMA user_version"
            ).fetchone()[0]
        )

        if existing_tables and current_version == 0:
            raise DatabaseSchemaError(
                "The existing database predates schema "
                "versioning and may use the old incompatible "
                "schema. Preserve or remove that database "
                "before creating the corrected schema."
            )

        if current_version not in (
            0,
            SCHEMA_VERSION,
        ):
            raise DatabaseSchemaError(
                "Unsupported database schema version "
                f"{current_version}; this code expects "
                f"version {SCHEMA_VERSION}."
            )

        try:
            connection.executescript(
                "BEGIN IMMEDIATE;\n"
                + SCHEMA_SQL
                + (
                    "\nPRAGMA user_version = "
                    f"{SCHEMA_VERSION};\n"
                )
                + "COMMIT;"
            )

        except Exception:
            if connection.in_transaction:
                connection.rollback()

            raise

        validate_database_schema(connection)

        return connection

    except Exception:
        connection.close()
        raise
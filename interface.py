"""Read-only Tkinter browser for the BACnet capture database.

The IP Devices view exposes communication peers, aggregate BACnet services,
and logical BACnet read/write conversations reconstructed for each endpoint.
Confirmed requests are matched to their responses by transport endpoints and
invoke ID. Segmented Confirmed-Request and ComplexACK payloads are reassembled
before values are decoded. Requests without actual returned/written data remain
hidden from the value table.
"""

from __future__ import annotations

import argparse
import sqlite3
import struct
import sys
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Final, Iterable, Mapping, Sequence

from bacnet_conversations import (
    READ_SERVICE_CHOICES,
    READ_WRITE_SERVICE_CHOICES,
    WRITE_SERVICE_CHOICES,
    build_bacnet_conversations,
    conversation_summary,
)
from database import (
    DEFAULT_DATABASE_PATH,
    DatabaseSchemaError,
    validate_database_schema,
)
from utils import format_dictionary


DEFAULT_PACKET_LIMIT: Final[int] = 2_000
ALL_CAPTURES_LABEL: Final[str] = "All captures"
ALL_STATUSES_LABEL: Final[str] = "All statuses"
ALL_SERVICE_FAMILIES_LABEL: Final[str] = "All families"
PACKET_STATUSES: Final[tuple[str, ...]] = (
    "parsed",
    "partial",
    "unsupported",
    "malformed",
    "error",
)



OBJECT_TYPE_NAMES: Final[dict[int, str]] = {
    0: "analog-input",
    1: "analog-output",
    2: "analog-value",
    3: "binary-input",
    4: "binary-output",
    5: "binary-value",
    8: "device",
    10: "file",
    13: "multi-state-input",
    14: "multi-state-output",
    19: "multi-state-value",
    20: "trend-log",
    30: "access-door",
    31: "timer",
    40: "characterstring-value",
    45: "integer-value",
    48: "large-analog-value",
    50: "octetstring-value",
    55: "positive-integer-value",
    56: "lighting-output",
    57: "binary-lighting-output",
    58: "network-port",
}

PROPERTY_IDENTIFIER_NAMES: Final[dict[int, str]] = {
    28: "description",
    36: "event-state",
    44: "firmware-revision",
    58: "location",
    62: "max-apdu-length-accepted",
    70: "model-name",
    73: "number-of-apdu-retries",
    74: "number-of-states",
    75: "object-identifier",
    76: "object-list",
    77: "object-name",
    79: "object-type",
    81: "out-of-service",
    85: "present-value",
    87: "priority-array",
    96: "protocol-object-types-supported",
    97: "protocol-services-supported",
    98: "protocol-version",
    103: "reliability",
    104: "relinquish-default",
    107: "segmentation-supported",
    111: "status-flags",
    112: "system-status",
    117: "units",
    119: "utc-offset",
    120: "vendor-identifier",
    121: "vendor-name",
    139: "protocol-revision",
}

APPLICATION_TAG_NAMES: Final[dict[int, str]] = {
    0: "null",
    1: "boolean",
    2: "unsigned",
    3: "signed",
    4: "real",
    5: "double",
    6: "octet-string",
    7: "character-string",
    8: "bit-string",
    9: "enumerated",
    10: "date",
    11: "time",
    12: "object-identifier",
}

PDU_PHASES: Final[dict[int, str]] = {
    0: "Request",
    1: "Request",
    2: "Simple ACK",
    3: "Complex ACK",
    4: "Segment ACK",
    5: "Error",
    6: "Reject",
    7: "Abort",
}


def _read_extended_length(data: bytes, offset: int) -> tuple[int, int]:
    """Read a BACnet extended length and return ``(length, new_offset)``."""
    if offset >= len(data):
        raise ValueError("BACnet tag is missing its extended length")

    first = data[offset]
    offset += 1

    if first <= 253:
        return first, offset

    if first == 254:
        if offset + 2 > len(data):
            raise ValueError("BACnet tag has a truncated 16-bit length")
        return int.from_bytes(data[offset : offset + 2], "big"), offset + 2

    if offset + 4 > len(data):
        raise ValueError("BACnet tag has a truncated 32-bit length")
    return int.from_bytes(data[offset : offset + 4], "big"), offset + 4


def _read_bacnet_tag(data: bytes, offset: int) -> tuple[dict[str, Any], int]:
    """Decode one BACnet application/context tag without losing raw bytes."""
    if offset >= len(data):
        raise ValueError("No BACnet tag remains at this offset")

    start = offset
    header = data[offset]
    offset += 1

    tag_number = (header >> 4) & 0x0F
    context_specific = bool(header & 0x08)
    length_value_type = header & 0x07

    if tag_number == 0x0F:
        if offset >= len(data):
            raise ValueError("BACnet tag is missing its extended tag number")
        tag_number = data[offset]
        offset += 1

    if context_specific and length_value_type == 6:
        return {
            "start": start,
            "end": offset,
            "tag_number": tag_number,
            "context": True,
            "kind": "opening",
            "value": b"",
        }, offset

    if context_specific and length_value_type == 7:
        return {
            "start": start,
            "end": offset,
            "tag_number": tag_number,
            "context": True,
            "kind": "closing",
            "value": b"",
        }, offset

    # Application Boolean encodes the Boolean value in the low three bits and
    # has no following value octets.
    if not context_specific and tag_number == 1:
        return {
            "start": start,
            "end": offset,
            "tag_number": tag_number,
            "context": False,
            "kind": "primitive",
            "value": b"",
            "boolean_value": bool(length_value_type),
        }, offset

    if length_value_type <= 4:
        value_length = length_value_type
    elif length_value_type == 5:
        value_length, offset = _read_extended_length(data, offset)
    else:
        raise ValueError("Reserved BACnet length/value/type encoding")

    value_end = offset + value_length
    if value_end > len(data):
        raise ValueError("BACnet tag value extends beyond the service payload")

    return {
        "start": start,
        "end": value_end,
        "tag_number": tag_number,
        "context": context_specific,
        "kind": "primitive",
        "value": data[offset:value_end],
    }, value_end


def _parse_bacnet_tags(data: bytes) -> tuple[list[dict[str, Any]], str | None]:
    """Parse every top-level encoded tag, retaining a useful error message."""
    tags: list[dict[str, Any]] = []
    offset = 0

    try:
        while offset < len(data):
            tag, offset = _read_bacnet_tag(data, offset)
            tags.append(tag)
    except ValueError as error:
        return tags, str(error)

    return tags, None


def _decode_unsigned(value: bytes) -> int | None:
    if not value:
        return 0
    if len(value) > 8:
        return None
    return int.from_bytes(value, "big", signed=False)


def _decode_object_identifier(value: bytes) -> tuple[int, int] | None:
    if len(value) != 4:
        return None

    encoded = int.from_bytes(value, "big")
    return (encoded >> 22) & 0x03FF, encoded & 0x3FFFFF


def _object_text(value: bytes) -> str:
    decoded = _decode_object_identifier(value)
    if decoded is None:
        return f"object-id({value.hex()})"

    object_type, instance = decoded
    name = OBJECT_TYPE_NAMES.get(object_type, f"object-type-{object_type}")
    return f"{name}:{instance}"


def _property_text(value: bytes) -> str:
    identifier = _decode_unsigned(value)
    if identifier is None:
        return f"property({value.hex()})"

    name = PROPERTY_IDENTIFIER_NAMES.get(identifier, f"property-{identifier}")
    return f"{name} ({identifier})"


def _decode_text_bytes(value: bytes) -> str:
    """Show printable payload bytes as text and binary payloads as hex."""
    if not value:
        return "<empty>"

    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        text = ""

    if text and all(character.isprintable() or character in "\r\n\t" for character in text):
        return text

    return "0x" + value.hex()


def _decode_character_string(value: bytes) -> str:
    """Decode the common BACnet character-set encodings."""
    if not value:
        return "<empty>"

    encoding = value[0]
    character_data = value[1:]

    try:
        if encoding == 4:
            return character_data.decode("utf-32-be")
        if encoding == 5:
            return character_data.decode("utf-16-be")
        if encoding == 0:
            try:
                return character_data.decode("utf-8")
            except UnicodeDecodeError:
                return character_data.decode("latin-1")
    except UnicodeDecodeError:
        pass

    return _decode_text_bytes(character_data)


def _decode_application_value(tag: Mapping[str, Any]) -> str:
    """Return the actual value represented by an application tag."""
    tag_number = int(tag["tag_number"])
    value = bytes(tag.get("value", b""))

    try:
        if tag_number == 0:
            return "NULL"
        if tag_number == 1:
            return "TRUE" if tag.get("boolean_value") else "FALSE"
        if tag_number == 2:
            return str(int.from_bytes(value, "big", signed=False))
        if tag_number == 3:
            return str(int.from_bytes(value, "big", signed=True))
        if tag_number == 4 and len(value) == 4:
            return f"{struct.unpack('>f', value)[0]:g}"
        if tag_number == 5 and len(value) == 8:
            return f"{struct.unpack('>d', value)[0]:g}"
        if tag_number == 6:
            return _decode_text_bytes(value)
        if tag_number == 7:
            return _decode_character_string(value)
        if tag_number == 8:
            if not value:
                return "<empty bit string>"
            unused = value[0]
            bits = "".join(f"{octet:08b}" for octet in value[1:])
            if unused:
                bits = bits[:-unused]
            return bits
        if tag_number == 9:
            return str(int.from_bytes(value, "big"))
        if tag_number == 10 and len(value) == 4:
            year, month, day, weekday = value
            year_text = "*" if year == 255 else str(1900 + year)
            return f"{year_text}-{month:02d}-{day:02d} (weekday {weekday})"
        if tag_number == 11 and len(value) == 4:
            hour, minute, second, hundredths = value
            return f"{hour:02d}:{minute:02d}:{second:02d}.{hundredths:02d}"
        if tag_number == 12:
            return _object_text(value)
    except (OverflowError, ValueError, struct.error):
        pass

    name = APPLICATION_TAG_NAMES.get(tag_number, f"application-{tag_number}")
    return f"{name}: 0x{value.hex()}"


def _values_inside_context(
    tags: Sequence[Mapping[str, Any]],
    context_number: int,
) -> list[str]:
    """Decode application values between a matching opening/closing tag pair."""
    depth = 0
    values: list[str] = []

    for tag in tags:
        if tag.get("context") and tag.get("tag_number") == context_number:
            if tag.get("kind") == "opening":
                depth += 1
                continue
            if tag.get("kind") == "closing" and depth:
                depth -= 1
                continue

        if depth and not tag.get("context") and tag.get("kind") == "primitive":
            values.append(_decode_application_value(tag))

    return values


def _summarize_items(items: Sequence[str], *, maximum: int = 3) -> str:
    unique: list[str] = []
    for item in items:
        if item and item not in unique:
            unique.append(item)

    if len(unique) <= maximum:
        return ", ".join(unique)

    return ", ".join(unique[:maximum]) + f" (+{len(unique) - maximum})"


def _application_tags_inside_context(
    tags: Sequence[Mapping[str, Any]],
    context_number: int,
) -> list[Mapping[str, Any]]:
    """Return primitive application tags inside a context wrapper."""
    depth = 0
    values: list[Mapping[str, Any]] = []

    for tag in tags:
        if tag.get("context") and int(tag.get("tag_number", -1)) == context_number:
            if tag.get("kind") == "opening":
                depth += 1
                continue
            if tag.get("kind") == "closing" and depth:
                depth -= 1
                continue

        if depth and not tag.get("context") and tag.get("kind") == "primitive":
            values.append(tag)

    return values


def _signed_application_value(tag: Mapping[str, Any]) -> int | None:
    if tag.get("context") or tag.get("kind") != "primitive":
        return None
    if int(tag.get("tag_number", -1)) != 3:
        return None
    value = bytes(tag.get("value", b""))
    if not value or len(value) > 8:
        return None
    return int.from_bytes(value, "big", signed=True)


def _unsigned_application_value(tag: Mapping[str, Any]) -> int | None:
    if tag.get("context") or tag.get("kind") != "primitive":
        return None
    if int(tag.get("tag_number", -1)) != 2:
        return None
    return _decode_unsigned(bytes(tag.get("value", b"")))


def _tag_tree(
    tags: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], str | None]:
    """Build a nested tree from BACnet opening and closing context tags."""
    roots: list[dict[str, Any]] = []
    stack: list[tuple[int | None, list[dict[str, Any]]]] = [(None, roots)]

    for original in tags:
        tag = dict(original)
        kind = str(tag.get("kind") or "primitive")
        number = int(tag.get("tag_number", -1))

        if kind == "opening" and tag.get("context"):
            node = {"tag": tag, "children": []}
            stack[-1][1].append(node)
            stack.append((number, node["children"]))
            continue

        if kind == "closing" and tag.get("context"):
            if len(stack) == 1:
                return roots, f"Unexpected closing context tag {number}"
            expected, _ = stack[-1]
            if expected != number:
                return roots, (
                    f"Closing context tag {number} does not match "
                    f"opening tag {expected}"
                )
            stack.pop()
            continue

        stack[-1][1].append({"tag": tag, "children": []})

    if len(stack) != 1:
        unclosed = ", ".join(str(number) for number, _ in stack[1:])
        return roots, f"Unclosed BACnet context tag(s): {unclosed}"

    return roots, None


def _node_tag(node: Mapping[str, Any]) -> Mapping[str, Any]:
    return node.get("tag", {})


def _node_context_number(node: Mapping[str, Any]) -> int | None:
    tag = _node_tag(node)
    if not tag.get("context"):
        return None
    return int(tag.get("tag_number", -1))


def _node_is_primitive(node: Mapping[str, Any]) -> bool:
    return str(_node_tag(node).get("kind") or "primitive") == "primitive"


def _primitive_context_value(node: Mapping[str, Any]) -> bytes:
    if not _node_is_primitive(node):
        return b""
    return bytes(_node_tag(node).get("value", b""))


def _top_context_primitive(
    nodes: Sequence[Mapping[str, Any]],
    context_number: int,
) -> Mapping[str, Any] | None:
    for node in nodes:
        if (
            _node_context_number(node) == context_number
            and _node_is_primitive(node)
        ):
            return node
    return None


def _top_context_constructed(
    nodes: Sequence[Mapping[str, Any]],
    context_number: int,
) -> Mapping[str, Any] | None:
    for node in nodes:
        if (
            _node_context_number(node) == context_number
            and not _node_is_primitive(node)
        ):
            return node
    return None


def _application_nodes(
    nodes: Sequence[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    results: list[Mapping[str, Any]] = []
    for node in nodes:
        tag = _node_tag(node)
        if _node_is_primitive(node) and not tag.get("context"):
            results.append(node)
        results.extend(_application_nodes(node.get("children", ())))
    return results


def _printable_runs(data: bytes, *, minimum: int = 4) -> list[str]:
    """Extract useful printable UTF-8/ASCII runs from otherwise opaque bytes."""
    runs: list[str] = []
    current = bytearray()

    def flush() -> None:
        nonlocal current
        if len(current) >= minimum:
            try:
                text = bytes(current).decode("utf-8")
            except UnicodeDecodeError:
                text = bytes(current).decode("latin-1", errors="replace")
            text = text.strip("\x00")
            if text and text not in runs:
                runs.append(text)
        current = bytearray()

    for octet in data:
        if 32 <= octet <= 126 or octet in (9, 10, 13):
            current.append(octet)
        else:
            flush()
    flush()
    return runs


def _decode_context_primitive(tag: Mapping[str, Any]) -> str:
    value = bytes(tag.get("value", b""))
    if not value:
        return "<empty>"

    printable = _printable_runs(value)
    if printable and sum(len(item) for item in printable) >= max(4, len(value) - 2):
        return "\n".join(printable)

    if len(value) <= 4:
        return f"{int.from_bytes(value, 'big')} (0x{value.hex()})"

    return "0x" + value.hex()


def _decode_value_nodes(
    nodes: Sequence[Mapping[str, Any]],
) -> list[str]:
    """Decode BACnet values recursively, preserving unknown context values."""
    values: list[str] = []

    for node in nodes:
        tag = _node_tag(node)
        children = node.get("children", ())

        if _node_is_primitive(node):
            if tag.get("context"):
                values.append(
                    f"context-{int(tag.get('tag_number', -1))}: "
                    f"{_decode_context_primitive(tag)}"
                )
            else:
                values.append(_decode_application_value(tag))
            continue

        nested = _decode_value_nodes(children)
        if nested:
            values.extend(nested)

    return values


def _raw_value_fallback(data: bytes, *, label: str = "Undecoded BACnet value") -> str:
    """Return human-readable text when possible, otherwise a lossless hex value."""
    printable = _printable_runs(data)
    if printable:
        return "\n".join(printable)
    if not data:
        return "<empty>"
    return f"{label}: 0x{data.hex()}"


def _property_item(
    *,
    operation: str,
    object_text: str = "",
    property_text: str = "",
    array_index: str = "",
    actual_data: str = "",
    priority: str = "",
    decode_quality: str = "decoded",
) -> dict[str, Any]:
    target_parts = [object_text, property_text]
    if array_index:
        target_parts.append(f"index {array_index}")
    return {
        "operation": operation,
        "object": object_text,
        "property": property_text,
        "array_index": array_index,
        "target": " / ".join(part for part in target_parts if part),
        "actual_data": actual_data,
        "value": actual_data,
        "priority": priority,
        "decode_quality": decode_quality,
        "has_actual_data": bool(actual_data),
    }


def _context_object_text(node: Mapping[str, Any] | None) -> str:
    if node is None:
        return ""
    value = _primitive_context_value(node)
    return _object_text(value) if len(value) == 4 else ""


def _context_property_text(node: Mapping[str, Any] | None) -> str:
    if node is None:
        return ""
    return _property_text(_primitive_context_value(node))


def _context_unsigned_text(node: Mapping[str, Any] | None) -> str:
    if node is None:
        return ""
    value = _decode_unsigned(_primitive_context_value(node))
    return "" if value is None else str(value)


def _decode_file_service_payload(
    service_choice: int,
    pdu_type_code: int,
    data: bytes,
    tags: Sequence[Mapping[str, Any]],
    parse_error: str | None,
) -> dict[str, Any]:
    """Decode AtomicReadFile and AtomicWriteFile payloads conservatively."""
    tree, tree_error = _tag_tree(tags)
    parse_error = parse_error or tree_error

    file_object = ""
    for node in tree:
        tag = _node_tag(node)
        if (
            _node_is_primitive(node)
            and not tag.get("context")
            and int(tag.get("tag_number", -1)) == 12
        ):
            file_object = _object_text(bytes(tag.get("value", b"")))
            break

    if not file_object:
        file_object = _context_object_text(_top_context_primitive(tree, 0))

    access_node = _top_context_constructed(tree, 0)
    access_name = "stream"
    if access_node is None:
        access_node = _top_context_constructed(tree, 1)
        access_name = "record"
    if access_node is None:
        access_name = ""

    position: int | None = None
    requested_count: int | None = None
    end_of_file: bool | None = None
    actual_values: list[str] = []

    if service_choice == 6 and pdu_type_code == 3:
        for node in tree:
            tag = _node_tag(node)
            if (
                _node_is_primitive(node)
                and not tag.get("context")
                and int(tag.get("tag_number", -1)) == 1
            ):
                end_of_file = bool(tag.get("boolean_value"))
                break

    if access_node is not None:
        children = list(access_node.get("children", ()))
        application_nodes = [
            node
            for node in children
            if _node_is_primitive(node) and not _node_tag(node).get("context")
        ]

        if application_nodes:
            first = _node_tag(application_nodes[0])
            if int(first.get("tag_number", -1)) == 3:
                position = _signed_application_value(first)

        if service_choice == 6 and pdu_type_code == 0 and len(application_nodes) >= 2:
            requested_count = _unsigned_application_value(
                _node_tag(application_nodes[1])
            )

        for node in application_nodes:
            tag = _node_tag(node)
            if int(tag.get("tag_number", -1)) == 6:
                actual_values.append(
                    _decode_text_bytes(bytes(tag.get("value", b"")))
                )

        # Some devices use context-specific file data. Keep it visible.
        if not actual_values:
            for node in children:
                tag = _node_tag(node)
                if _node_is_primitive(node) and tag.get("context"):
                    value = bytes(tag.get("value", b""))
                    if value:
                        actual_values.append(_decode_text_bytes(value))

    actual_data = "\n".join(value for value in actual_values if value)

    # Complete AtomicWriteFile requests must never disappear merely because a
    # vendor uses an unfamiliar encoding. Preserve a useful raw fallback.
    if service_choice == 7 and pdu_type_code == 0 and not actual_data and data:
        actual_data = _raw_value_fallback(data)

    target_parts = [file_object]
    if access_name and position is not None:
        unit = "byte" if access_name == "stream" else "record"
        target_parts.append(f"{unit} {position}")

    operation = "Read File" if service_choice == 6 else "Write File"
    item = _property_item(
        operation=operation,
        object_text=file_object,
        property_text="file-data",
        actual_data=actual_data,
        decode_quality=("decoded" if actual_values else "raw-fallback"),
    )
    item["target"] = " @ ".join(part for part in target_parts if part)

    return {
        **item,
        "items": [item] if actual_data else [],
        "access_method": access_name,
        "file_position": position,
        "requested_count": requested_count,
        "end_of_file": end_of_file,
        "has_actual_data": bool(actual_data),
        "parse_error": parse_error,
        "tag_count": len(tags),
        "raw_service_data": data,
    }


def _decode_single_property_service(
    service_choice: int,
    pdu_type_code: int,
    data: bytes,
    tree: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    object_text = _context_object_text(_top_context_primitive(tree, 0))
    property_text = _context_property_text(_top_context_primitive(tree, 1))
    array_index = _context_unsigned_text(_top_context_primitive(tree, 2))
    priority = _context_unsigned_text(_top_context_primitive(tree, 4))

    value_context = 3
    value_node = _top_context_constructed(tree, value_context)
    actual_values = _decode_value_nodes(value_node.get("children", ())) if value_node else []
    actual_data = "\n".join(value for value in actual_values if value)
    quality = "decoded"

    is_write_request = service_choice == 15 and pdu_type_code == 0
    is_read_response = service_choice == 12 and pdu_type_code == 3

    if (is_write_request or is_read_response) and not actual_data and data:
        actual_data = _raw_value_fallback(data)
        quality = "raw-fallback"

    item = _property_item(
        operation=_service_operation_name(service_choice),
        object_text=object_text,
        property_text=property_text,
        array_index=array_index,
        actual_data=actual_data,
        priority=priority,
        decode_quality=quality,
    )
    return [item]


def _decode_read_property_multiple(
    pdu_type_code: int,
    data: bytes,
    tree: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    current_object = ""

    for node in tree:
        context = _node_context_number(node)
        if context == 0 and _node_is_primitive(node):
            current_object = _context_object_text(node)
            continue

        if context != 1 or _node_is_primitive(node):
            continue

        children = list(node.get("children", ()))
        index = 0
        while index < len(children):
            child = children[index]
            child_context = _node_context_number(child)

            if pdu_type_code == 0:
                if child_context != 0 or not _node_is_primitive(child):
                    index += 1
                    continue
                property_text = _context_property_text(child)
                array_index = ""
                if index + 1 < len(children) and _node_context_number(children[index + 1]) == 1:
                    array_index = _context_unsigned_text(children[index + 1])
                    index += 1
                items.append(
                    _property_item(
                        operation="Read Property Multiple",
                        object_text=current_object,
                        property_text=property_text,
                        array_index=array_index,
                    )
                )
                index += 1
                continue

            # ComplexACK ReadAccessResult uses property-id [2], optional
            # array-index [3], and either property-value [4] or error [5].
            if child_context != 2 or not _node_is_primitive(child):
                index += 1
                continue

            property_text = _context_property_text(child)
            array_index = ""
            actual_data = ""
            quality = "decoded"
            cursor = index + 1

            if cursor < len(children) and _node_context_number(children[cursor]) == 3:
                array_index = _context_unsigned_text(children[cursor])
                cursor += 1

            if cursor < len(children):
                value_or_error = children[cursor]
                context_number = _node_context_number(value_or_error)
                if context_number == 4 and not _node_is_primitive(value_or_error):
                    values = _decode_value_nodes(value_or_error.get("children", ()))
                    actual_data = "\n".join(value for value in values if value)
                elif context_number == 5:
                    values = _decode_value_nodes(value_or_error.get("children", ()))
                    actual_data = "BACnet error: " + (", ".join(values) or "unknown")

            if not actual_data:
                actual_data = _raw_value_fallback(data)
                quality = "raw-fallback"

            items.append(
                _property_item(
                    operation="Read Property Multiple",
                    object_text=current_object,
                    property_text=property_text,
                    array_index=array_index,
                    actual_data=actual_data,
                    decode_quality=quality,
                )
            )
            index = max(cursor + 1, index + 1)

    return items


def _decode_write_property_multiple(
    pdu_type_code: int,
    data: bytes,
    tree: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if pdu_type_code != 0:
        return []

    items: list[dict[str, Any]] = []
    current_object = ""

    for node in tree:
        context = _node_context_number(node)
        if context == 0 and _node_is_primitive(node):
            current_object = _context_object_text(node)
            continue

        if context != 1 or _node_is_primitive(node):
            continue

        children = list(node.get("children", ()))
        index = 0
        while index < len(children):
            property_node = children[index]
            if _node_context_number(property_node) != 0 or not _node_is_primitive(property_node):
                index += 1
                continue

            property_text = _context_property_text(property_node)
            array_index = ""
            priority = ""
            actual_data = ""
            quality = "decoded"
            cursor = index + 1

            if cursor < len(children) and _node_context_number(children[cursor]) == 1:
                array_index = _context_unsigned_text(children[cursor])
                cursor += 1

            if cursor < len(children) and _node_context_number(children[cursor]) == 2:
                value_node = children[cursor]
                if not _node_is_primitive(value_node):
                    values = _decode_value_nodes(value_node.get("children", ()))
                    actual_data = "\n".join(value for value in values if value)
                else:
                    actual_data = _decode_context_primitive(_node_tag(value_node))
                cursor += 1

            if cursor < len(children) and _node_context_number(children[cursor]) == 3:
                priority = _context_unsigned_text(children[cursor])
                cursor += 1

            if not actual_data:
                # Preserve the complete request instead of hiding the write.
                actual_data = _raw_value_fallback(data)
                quality = "raw-fallback"

            items.append(
                _property_item(
                    operation="Write Property Multiple",
                    object_text=current_object,
                    property_text=property_text,
                    array_index=array_index,
                    actual_data=actual_data,
                    priority=priority,
                    decode_quality=quality,
                )
            )
            index = max(cursor, index + 1)

    if not items and data:
        items.append(
            _property_item(
                operation="Write Property Multiple",
                actual_data=_raw_value_fallback(data),
                decode_quality="raw-fallback",
            )
        )

    return items


def decode_service_payload(
    service_choice: int,
    pdu_type_code: int,
    raw_service_data: bytes | None,
) -> dict[str, Any]:
    """Decode useful BACnet read/write data and retain unknown complete writes."""
    data = b"" if raw_service_data is None else bytes(raw_service_data)
    tags, parse_error = _parse_bacnet_tags(data)

    if service_choice in (6, 7):
        return _decode_file_service_payload(
            service_choice,
            pdu_type_code,
            data,
            tags,
            parse_error,
        )

    tree, tree_error = _tag_tree(tags)
    parse_error = parse_error or tree_error

    if service_choice in (12, 15):
        items = _decode_single_property_service(
            service_choice,
            pdu_type_code,
            data,
            tree,
        )
    elif service_choice == 14:
        items = _decode_read_property_multiple(
            pdu_type_code,
            data,
            tree,
        )
    elif service_choice == 16:
        items = _decode_write_property_multiple(
            pdu_type_code,
            data,
            tree,
        )
    else:
        items = []

    value_items = [item for item in items if item.get("has_actual_data")]
    actual_data = "\n".join(
        str(item.get("actual_data") or "")
        for item in value_items
        if item.get("actual_data") not in (None, "")
    )
    object_text = _summarize_items(
        [str(item.get("object") or "") for item in items]
    )
    property_text = _summarize_items(
        [str(item.get("property") or "") for item in items]
    )
    target_text = _summarize_items(
        [str(item.get("target") or "") for item in items]
    )
    priority_text = _summarize_items(
        [str(item.get("priority") or "") for item in items]
    )

    return {
        "operation": _service_operation_name(service_choice),
        "object": object_text,
        "property": property_text,
        "array_index": "",
        "value": actual_data,
        "actual_data": actual_data,
        "target": target_text,
        "priority": priority_text,
        "items": items,
        "has_actual_data": bool(value_items),
        "parse_error": parse_error,
        "tag_count": len(tags),
        "raw_service_data": data,
    }


def _service_operation_name(service_choice: int) -> str:
    return {
        6: "Read File",
        7: "Write File",
        12: "Read Property",
        14: "Read Property Multiple",
        15: "Write Property",
        16: "Write Property Multiple",
    }.get(service_choice, f"Service {service_choice}")


def _table_preview(value: Any, *, maximum: int = 180) -> str:
    """Keep actual values readable inside a one-line Treeview cell."""
    text = str(value or "").replace("\\", "\\\\")
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    if len(text) > maximum:
        return text[: maximum - 1] + "…"
    return text


class DatabaseOpenError(RuntimeError):
    """Raised when the requested BACnet database cannot be opened safely."""


class BacnetRepository:
    """Read-only query layer used by the Tkinter interface."""

    def __init__(self, database_path: str | Path) -> None:
        path = Path(database_path).expanduser().resolve()

        if not path.is_file():
            raise DatabaseOpenError(f"Database file does not exist: {path}")

        try:
            connection = sqlite3.connect(
                f"{path.as_uri()}?mode=ro",
                uri=True,
                timeout=5.0,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA query_only = ON")
            validate_database_schema(connection)
        except (sqlite3.Error, DatabaseSchemaError) as error:
            try:
                connection.close()
            except (UnboundLocalError, sqlite3.Error):
                pass
            raise DatabaseOpenError(str(error)) from error

        self.path = path
        self.connection = connection

    def close(self) -> None:
        """Close the read-only database handle."""
        self.connection.close()

    def captures(self) -> list[sqlite3.Row]:
        return self.connection.execute(
            """
            SELECT
                capture_id,
                filename,
                imported_at,
                capture_start,
                capture_end,
                packet_count,
                link_type,
                notes
            FROM captures
            ORDER BY imported_at DESC, capture_id DESC
            """
        ).fetchall()

    def overview(self, capture_id: int | None) -> dict[str, Any]:
        params = (capture_id, capture_id)

        packet_summary = self.connection.execute(
            """
            SELECT
                COUNT(*) AS packet_count,
                COUNT(DISTINCT i.source_ip) AS source_count,
                COUNT(DISTINCT i.destination_ip) AS destination_count,
                COUNT(DISTINCT CASE
                    WHEN i.source_ip IS NOT NULL THEN i.source_ip
                END)
                + COUNT(DISTINCT CASE
                    WHEN i.destination_ip IS NOT NULL
                         AND i.destination_ip NOT IN (
                             SELECT i2.source_ip
                             FROM packets p2
                             JOIN ip_headers i2 ON i2.packet_id = p2.packet_id
                             WHERE (? IS NULL OR p2.capture_id = ?)
                         )
                    THEN i.destination_ip
                END) AS endpoint_count,
                SUM(CASE WHEN b.packet_id IS NOT NULL THEN 1 ELSE 0 END)
                    AS bvlc_count,
                SUM(CASE WHEN n.packet_id IS NOT NULL THEN 1 ELSE 0 END)
                    AS npdu_count,
                SUM(CASE WHEN a.packet_id IS NOT NULL THEN 1 ELSE 0 END)
                    AS apdu_count,
                MIN(p.timestamp) AS first_seen,
                MAX(p.timestamp) AS last_seen
            FROM packets p
            LEFT JOIN ip_headers i ON i.packet_id = p.packet_id
            LEFT JOIN bvlc_headers b ON b.packet_id = p.packet_id
            LEFT JOIN npdu_headers n ON n.packet_id = p.packet_id
            LEFT JOIN apdu_headers a ON a.packet_id = p.packet_id
            WHERE (? IS NULL OR p.capture_id = ?)
            """,
            params + params,
        ).fetchone()

        status_rows = self.connection.execute(
            """
            SELECT parse_status, COUNT(*) AS packet_count
            FROM packets
            WHERE (? IS NULL OR capture_id = ?)
            GROUP BY parse_status
            """,
            params,
        ).fetchall()

        summary = dict(packet_summary) if packet_summary is not None else {}
        summary["status_counts"] = {
            row["parse_status"]: row["packet_count"] for row in status_rows
        }
        return summary

    def devices(self, capture_id: int | None) -> list[sqlite3.Row]:
        params = (capture_id, capture_id)
        return self.connection.execute(
            """
            WITH traffic AS (
                SELECT
                    i.source_ip AS ip_address,
                    i.destination_ip AS peer_address,
                    1 AS sent,
                    0 AS received,
                    p.timestamp
                FROM packets p
                JOIN ip_headers i ON i.packet_id = p.packet_id
                WHERE i.source_ip IS NOT NULL
                  AND (? IS NULL OR p.capture_id = ?)

                UNION ALL

                SELECT
                    i.destination_ip AS ip_address,
                    i.source_ip AS peer_address,
                    0 AS sent,
                    1 AS received,
                    p.timestamp
                FROM packets p
                JOIN ip_headers i ON i.packet_id = p.packet_id
                WHERE i.destination_ip IS NOT NULL
                  AND (? IS NULL OR p.capture_id = ?)
            )
            SELECT
                ip_address,
                SUM(sent) AS sent_packets,
                SUM(received) AS received_packets,
                COUNT(*) AS total_packets,
                COUNT(DISTINCT peer_address) AS peer_count,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen
            FROM traffic
            GROUP BY ip_address
            ORDER BY total_packets DESC, ip_address
            """,
            params + params,
        ).fetchall()

    def device_peers(
        self,
        ip_address: str,
        capture_id: int | None,
    ) -> list[sqlite3.Row]:
        return self.connection.execute(
            """
            WITH traffic AS (
                SELECT
                    i.destination_ip AS peer_address,
                    1 AS sent,
                    0 AS received,
                    p.timestamp,
                    a.service_family,
                    a.service_choice
                FROM packets p
                JOIN ip_headers i ON i.packet_id = p.packet_id
                LEFT JOIN apdu_headers a ON a.packet_id = p.packet_id
                WHERE i.source_ip = ?
                  AND (? IS NULL OR p.capture_id = ?)

                UNION ALL

                SELECT
                    i.source_ip AS peer_address,
                    0 AS sent,
                    1 AS received,
                    p.timestamp,
                    a.service_family,
                    a.service_choice
                FROM packets p
                JOIN ip_headers i ON i.packet_id = p.packet_id
                LEFT JOIN apdu_headers a ON a.packet_id = p.packet_id
                WHERE i.destination_ip = ?
                  AND (? IS NULL OR p.capture_id = ?)
            )
            SELECT
                peer_address,
                SUM(sent) AS sent_packets,
                SUM(received) AS received_packets,
                COUNT(*) AS total_packets,
                COUNT(DISTINCT CASE
                    WHEN service_choice IS NOT NULL
                    THEN COALESCE(service_family, '') || ':' || service_choice
                END) AS service_count,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen
            FROM traffic
            WHERE peer_address IS NOT NULL
            GROUP BY peer_address
            ORDER BY total_packets DESC, peer_address
            """,
            (
                ip_address,
                capture_id,
                capture_id,
                ip_address,
                capture_id,
                capture_id,
            ),
        ).fetchall()

    def device_services(
        self,
        ip_address: str,
        capture_id: int | None,
    ) -> list[sqlite3.Row]:
        """Summarize services by APDU role instead of ambiguous direction.

        A SimpleACK for WriteProperty carries service choice 15 but does not
        contain the value that was written. Splitting requests and responses
        prevents a pair of outbound ACKs from looking like two outbound write
        requests in the interface.
        """
        return self.connection.execute(
            """
            SELECT
                a.service_family,
                a.service_choice,
                COALESCE(s.service_name, 'Unknown Service') AS service_name,
                SUM(
                    CASE
                        WHEN a.pdu_type_code IN (0, 1)
                         AND i.source_ip = ?
                        THEN 1 ELSE 0
                    END
                ) AS requests_sent,
                SUM(
                    CASE
                        WHEN a.pdu_type_code IN (0, 1)
                         AND i.destination_ip = ?
                        THEN 1 ELSE 0
                    END
                ) AS requests_received,
                SUM(
                    CASE
                        WHEN a.pdu_type_code IN (2, 3, 5, 6, 7)
                         AND i.source_ip = ?
                        THEN 1 ELSE 0
                    END
                ) AS responses_sent,
                SUM(
                    CASE
                        WHEN a.pdu_type_code IN (2, 3, 5, 6, 7)
                         AND i.destination_ip = ?
                        THEN 1 ELSE 0
                    END
                ) AS responses_received,
                COUNT(*) AS total_packets,
                MIN(p.timestamp) AS first_seen,
                MAX(p.timestamp) AS last_seen
            FROM packets p
            JOIN ip_headers i ON i.packet_id = p.packet_id
            JOIN apdu_headers a ON a.packet_id = p.packet_id
            LEFT JOIN bacnet_services s
              ON s.service_family = a.service_family
             AND s.service_code = a.service_choice
            WHERE a.service_choice IS NOT NULL
              AND (i.source_ip = ? OR i.destination_ip = ?)
              AND (? IS NULL OR p.capture_id = ?)
            GROUP BY a.service_family, a.service_choice, service_name
            ORDER BY total_packets DESC, a.service_family, a.service_choice
            """,
            (
                ip_address,
                ip_address,
                ip_address,
                ip_address,
                ip_address,
                ip_address,
                capture_id,
                capture_id,
            ),
        ).fetchall()


    def device_conversation_packets(
        self,
        ip_address: str,
        capture_id: int | None,
    ) -> list[sqlite3.Row]:
        """Return APDUs needed to reconstruct read/write conversations.

        Requests and service-bearing responses are restricted to the supported
        read/write services. SegmentACK, Reject, and Abort packets are also
        returned because they can acknowledge or terminate one of those
        conversations even though they do not contain a service choice.
        """
        service_choices = sorted(READ_WRITE_SERVICE_CHOICES)
        placeholders = ", ".join("?" for _ in service_choices)

        conditions = [
            "(i.source_ip = ? OR i.destination_ip = ?)",
            f"""(
                (
                    a.pdu_type_code IN (0, 2, 3, 5)
                    AND a.service_choice IN ({placeholders})
                )
                OR a.pdu_type_code IN (4, 6, 7)
            )""",
        ]
        parameters: list[Any] = [
            ip_address,
            ip_address,
            *service_choices,
        ]

        if capture_id is not None:
            conditions.append("p.capture_id = ?")
            parameters.append(capture_id)

        return self.connection.execute(
            f"""
            SELECT
                p.packet_id,
                p.capture_id,
                p.packet_number,
                p.timestamp,
                p.parse_status,
                i.source_ip,
                i.destination_ip,
                u.source_port,
                u.destination_port,
                a.first_byte,
                a.pdu_type_code,
                COALESCE(at.pdu_type_name, 'Unknown APDU Type')
                    AS pdu_type_name,
                a.invoke_id,
                a.segmented_message,
                a.more_follows,
                a.sequence_number,
                a.proposed_window_size,
                a.actual_window_size,
                a.negative_ack,
                a.server,
                a.service_family,
                a.service_choice,
                COALESCE(bs.service_name, 'Unknown Service')
                    AS service_name,
                a.error_class,
                a.error_code,
                a.reject_reason,
                a.abort_reason,
                a.raw_service_data
            FROM packets p
            JOIN ip_headers i ON i.packet_id = p.packet_id
            JOIN apdu_headers a ON a.packet_id = p.packet_id
            LEFT JOIN udp_headers u ON u.packet_id = p.packet_id
            LEFT JOIN apdu_types at
              ON at.pdu_type_code = a.pdu_type_code
            LEFT JOIN bacnet_services bs
              ON bs.service_family = a.service_family
             AND bs.service_code = a.service_choice
            WHERE {' AND '.join(conditions)}
            ORDER BY p.timestamp, p.capture_id, p.packet_number
            """,
            parameters,
        ).fetchall()

    def communications(self, capture_id: int | None) -> list[sqlite3.Row]:
        return self.connection.execute(
            """
            SELECT
                i.source_ip,
                i.destination_ip,
                COUNT(*) AS packet_count,
                COUNT(DISTINCT CASE
                    WHEN a.service_choice IS NOT NULL
                    THEN COALESCE(a.service_family, '') || ':' || a.service_choice
                END) AS service_count,
                MIN(p.timestamp) AS first_seen,
                MAX(p.timestamp) AS last_seen
            FROM packets p
            JOIN ip_headers i ON i.packet_id = p.packet_id
            LEFT JOIN apdu_headers a ON a.packet_id = p.packet_id
            WHERE (? IS NULL OR p.capture_id = ?)
            GROUP BY i.source_ip, i.destination_ip
            ORDER BY packet_count DESC, i.source_ip, i.destination_ip
            """,
            (capture_id, capture_id),
        ).fetchall()

    def services(self, capture_id: int | None) -> list[sqlite3.Row]:
        return self.connection.execute(
            """
            SELECT
                a.service_family,
                a.service_choice,
                COALESCE(s.service_name, 'Unknown Service') AS service_name,
                COUNT(*) AS packet_count,
                COUNT(DISTINCT i.source_ip) AS source_count,
                COUNT(DISTINCT i.destination_ip) AS destination_count,
                MIN(p.timestamp) AS first_seen,
                MAX(p.timestamp) AS last_seen
            FROM packets p
            JOIN apdu_headers a ON a.packet_id = p.packet_id
            LEFT JOIN ip_headers i ON i.packet_id = p.packet_id
            LEFT JOIN bacnet_services s
              ON s.service_family = a.service_family
             AND s.service_code = a.service_choice
            WHERE a.service_choice IS NOT NULL
              AND (? IS NULL OR p.capture_id = ?)
            GROUP BY a.service_family, a.service_choice, service_name
            ORDER BY packet_count DESC, a.service_family, a.service_choice
            """,
            (capture_id, capture_id),
        ).fetchall()

    def service_endpoints(
        self,
        service_family: str,
        service_choice: int,
        capture_id: int | None,
    ) -> list[sqlite3.Row]:
        return self.connection.execute(
            """
            WITH traffic AS (
                SELECT
                    i.source_ip AS ip_address,
                    1 AS sent,
                    0 AS received,
                    p.timestamp
                FROM packets p
                JOIN apdu_headers a ON a.packet_id = p.packet_id
                JOIN ip_headers i ON i.packet_id = p.packet_id
                WHERE a.service_family = ?
                  AND a.service_choice = ?
                  AND (? IS NULL OR p.capture_id = ?)

                UNION ALL

                SELECT
                    i.destination_ip AS ip_address,
                    0 AS sent,
                    1 AS received,
                    p.timestamp
                FROM packets p
                JOIN apdu_headers a ON a.packet_id = p.packet_id
                JOIN ip_headers i ON i.packet_id = p.packet_id
                WHERE a.service_family = ?
                  AND a.service_choice = ?
                  AND (? IS NULL OR p.capture_id = ?)
            )
            SELECT
                ip_address,
                SUM(sent) AS sent_packets,
                SUM(received) AS received_packets,
                COUNT(*) AS total_packets,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen
            FROM traffic
            WHERE ip_address IS NOT NULL
            GROUP BY ip_address
            ORDER BY total_packets DESC, ip_address
            """,
            (
                service_family,
                service_choice,
                capture_id,
                capture_id,
                service_family,
                service_choice,
                capture_id,
                capture_id,
            ),
        ).fetchall()

    @staticmethod
    def _packet_filter_sql(
        *,
        capture_id: int | None,
        parse_status: str | None,
        device: str | None,
        service_family: str | None,
        service_choice: int | None,
    ) -> tuple[str, list[Any]]:
        conditions: list[str] = []
        parameters: list[Any] = []

        if capture_id is not None:
            conditions.append("p.capture_id = ?")
            parameters.append(capture_id)

        if parse_status:
            conditions.append("p.parse_status = ?")
            parameters.append(parse_status)

        if device:
            conditions.append("(i.source_ip = ? OR i.destination_ip = ?)")
            parameters.extend((device, device))

        if service_family:
            conditions.append("a.service_family = ?")
            parameters.append(service_family)

        if service_choice is not None:
            conditions.append("a.service_choice = ?")
            parameters.append(service_choice)

        if not conditions:
            return "", parameters

        return "WHERE " + " AND ".join(conditions), parameters

    def packet_count(
        self,
        *,
        capture_id: int | None,
        parse_status: str | None,
        device: str | None,
        service_family: str | None,
        service_choice: int | None,
    ) -> int:
        where_sql, parameters = self._packet_filter_sql(
            capture_id=capture_id,
            parse_status=parse_status,
            device=device,
            service_family=service_family,
            service_choice=service_choice,
        )
        row = self.connection.execute(
            f"""
            SELECT COUNT(*) AS packet_count
            FROM packets p
            LEFT JOIN ip_headers i ON i.packet_id = p.packet_id
            LEFT JOIN apdu_headers a ON a.packet_id = p.packet_id
            {where_sql}
            """,
            parameters,
        ).fetchone()
        return int(row["packet_count"])

    def packets(
        self,
        *,
        capture_id: int | None,
        parse_status: str | None,
        device: str | None,
        service_family: str | None,
        service_choice: int | None,
        limit: int,
    ) -> list[sqlite3.Row]:
        where_sql, parameters = self._packet_filter_sql(
            capture_id=capture_id,
            parse_status=parse_status,
            device=device,
            service_family=service_family,
            service_choice=service_choice,
        )
        parameters.append(limit)

        return self.connection.execute(
            f"""
            SELECT
                p.packet_id,
                p.capture_id,
                p.packet_number,
                p.timestamp,
                p.parse_status,
                i.source_ip,
                i.destination_ip,
                u.source_port,
                u.destination_port,
                COALESCE(bf.function_name, 'Unknown BVLC Function')
                    AS bvlc_function,
                COALESCE(at.pdu_type_name, 'Unknown APDU Type')
                    AS apdu_type,
                a.service_family,
                a.service_choice,
                COALESCE(bs.service_name, '') AS service_name
            FROM packets p
            LEFT JOIN ip_headers i ON i.packet_id = p.packet_id
            LEFT JOIN udp_headers u ON u.packet_id = p.packet_id
            LEFT JOIN bvlc_headers b ON b.packet_id = p.packet_id
            LEFT JOIN bvlc_functions bf
              ON bf.type_code = b.bvlc_type_code
             AND bf.function_code = b.function_code
            LEFT JOIN apdu_headers a ON a.packet_id = p.packet_id
            LEFT JOIN apdu_types at ON at.pdu_type_code = a.pdu_type_code
            LEFT JOIN bacnet_services bs
              ON bs.service_family = a.service_family
             AND bs.service_code = a.service_choice
            {where_sql}
            ORDER BY p.capture_id, p.packet_number
            LIMIT ?
            """,
            parameters,
        ).fetchall()

    def packet_detail(self, packet_id: int) -> dict[str, Any] | None:
        packet = self.connection.execute(
            "SELECT * FROM packets WHERE packet_id = ?",
            (packet_id,),
        ).fetchone()
        if packet is None:
            return None

        def one(table: str) -> dict[str, Any] | None:
            row = self.connection.execute(
                f'SELECT * FROM "{table}" WHERE packet_id = ?',
                (packet_id,),
            ).fetchone()
            return None if row is None else dict(row)

        capture = self.connection.execute(
            "SELECT * FROM captures WHERE capture_id = ?",
            (packet["capture_id"],),
        ).fetchone()

        bvlc = self.connection.execute(
            """
            SELECT
                b.*,
                bt.type_name,
                bf.function_name,
                br.result_name
            FROM bvlc_headers b
            LEFT JOIN bvlc_types bt
              ON bt.type_code = b.bvlc_type_code
            LEFT JOIN bvlc_functions bf
              ON bf.type_code = b.bvlc_type_code
             AND bf.function_code = b.function_code
            LEFT JOIN bvlc_result_codes br
              ON br.type_code = b.bvlc_type_code
             AND br.result_code = b.result_code
            WHERE b.packet_id = ?
            """,
            (packet_id,),
        ).fetchone()

        npdu = self.connection.execute(
            """
            SELECT
                n.*,
                pr.priority_name,
                nm.message_name AS network_message_name
            FROM npdu_headers n
            LEFT JOIN npdu_priorities pr
              ON pr.priority_code = n.priority_code
            LEFT JOIN npdu_network_messages nm
              ON nm.message_type = n.network_message_type
            WHERE n.packet_id = ?
            """,
            (packet_id,),
        ).fetchone()

        apdu = self.connection.execute(
            """
            SELECT
                a.*,
                at.pdu_type_name,
                bs.service_name
            FROM apdu_headers a
            LEFT JOIN apdu_types at
              ON at.pdu_type_code = a.pdu_type_code
            LEFT JOIN bacnet_services bs
              ON bs.service_family = a.service_family
             AND bs.service_code = a.service_choice
            WHERE a.packet_id = ?
            """,
            (packet_id,),
        ).fetchone()

        errors = self.connection.execute(
            "SELECT * FROM parse_errors WHERE packet_id = ? ORDER BY error_id",
            (packet_id,),
        ).fetchall()
        bdt_entries = self.connection.execute(
            """
            SELECT *
            FROM bvlc_bdt_entries
            WHERE packet_id = ?
            ORDER BY entry_number
            """,
            (packet_id,),
        ).fetchall()
        fdt_entries = self.connection.execute(
            """
            SELECT *
            FROM bvlc_fdt_entries
            WHERE packet_id = ?
            ORDER BY entry_number
            """,
            (packet_id,),
        ).fetchall()

        return {
            "capture": None if capture is None else dict(capture),
            "packet": dict(packet),
            "ethernet": one("ethernet_headers"),
            "ip": one("ip_headers"),
            "udp": one("udp_headers"),
            "bvlc": None if bvlc is None else dict(bvlc),
            "bdt_entries": [dict(row) for row in bdt_entries],
            "fdt_entries": [dict(row) for row in fdt_entries],
            "npdu": None if npdu is None else dict(npdu),
            "apdu": None if apdu is None else dict(apdu),
            "parse_errors": [dict(row) for row in errors],
        }


class BacnetBrowserApp:
    """Tkinter application for browsing one BACnet SQLite database."""

    def __init__(
        self,
        root: tk.Tk,
        repository: BacnetRepository,
        *,
        packet_limit: int = DEFAULT_PACKET_LIMIT,
    ) -> None:
        self.root = root
        self.repository = repository
        self.packet_limit = packet_limit
        self.capture_by_label: dict[str, int | None] = {
            ALL_CAPTURES_LABEL: None
        }

        self.capture_var = tk.StringVar(value=ALL_CAPTURES_LABEL)
        self.database_var = tk.StringVar(value=str(repository.path))
        self.status_var = tk.StringVar(value="Ready")
        self.packet_status_var = tk.StringVar(value=ALL_STATUSES_LABEL)
        self.packet_device_var = tk.StringVar()
        self.packet_family_var = tk.StringVar(
            value=ALL_SERVICE_FAMILIES_LABEL
        )
        self.packet_service_code_var = tk.StringVar()
        self.selected_device_var = tk.StringVar(
            value="Select an IP endpoint to inspect its peers and services."
        )
        self.selected_device_service_var = tk.StringVar(
            value="Select a read/write service, or show all actual values."
        )
        self.selected_device_ip: str | None = None
        self.device_activity_rows: dict[str, dict[str, Any]] = {}
        self.selected_service_var = tk.StringVar(
            value="Select a service to list participating endpoints."
        )

        self._configure_root()
        self._configure_style()
        self._build_menu()
        self._build_layout()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.refresh_all()

    def _configure_root(self) -> None:
        self.root.title("BACnet Capture Browser")
        self.root.geometry("1450x880")
        self.root.minsize(1050, 650)

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Treeview", rowheight=24)
        style.configure("Heading.TLabel", font=("TkDefaultFont", 11, "bold"))
        style.configure("Metric.TLabel", font=("TkDefaultFont", 13, "bold"))

    def _build_menu(self) -> None:
        menu_bar = tk.Menu(self.root)
        file_menu = tk.Menu(menu_bar, tearoff=False)
        file_menu.add_command(label="Open database...", command=self.open_database)
        file_menu.add_command(label="Refresh", command=self.refresh_all)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.close)
        menu_bar.add_cascade(label="File", menu=file_menu)
        self.root.config(menu=menu_bar)

    def _build_layout(self) -> None:
        header = ttk.Frame(self.root, padding=(10, 8))
        header.pack(fill="x")

        ttk.Label(header, text="Database:").grid(row=0, column=0, sticky="w")
        ttk.Label(
            header,
            textvariable=self.database_var,
        ).grid(row=0, column=1, sticky="ew", padx=(6, 16))

        ttk.Label(header, text="Capture:").grid(row=0, column=2, sticky="e")
        self.capture_combo = ttk.Combobox(
            header,
            textvariable=self.capture_var,
            state="readonly",
            width=44,
        )
        self.capture_combo.grid(row=0, column=3, sticky="ew", padx=6)
        self.capture_combo.bind("<<ComboboxSelected>>", self._capture_changed)

        ttk.Button(header, text="Refresh", command=self.refresh_all).grid(
            row=0,
            column=4,
            padx=(8, 0),
        )
        header.columnconfigure(1, weight=1)
        header.columnconfigure(3, weight=1)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        self._build_overview_tab()
        self._build_devices_tab()
        self._build_communications_tab()
        self._build_services_tab()
        self._build_packets_tab()

        status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief="sunken",
            anchor="w",
            padding=(8, 3),
        )
        status_bar.pack(fill="x", side="bottom")

    @staticmethod
    def _tree_panel(
        parent: tk.Misc,
        columns: Sequence[str],
        headings: Sequence[str],
        widths: Sequence[int],
        *,
        anchors: Sequence[str] | None = None,
        height: int | None = None,
    ) -> tuple[ttk.Frame, ttk.Treeview]:
        frame = ttk.Frame(parent)
        tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
            selectmode="browse",
            height=height,
        )
        vertical = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(
            frame,
            orient="horizontal",
            command=tree.xview,
        )
        tree.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set,
        )
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        resolved_anchors = anchors or tuple("w" for _ in columns)
        for column, heading, width, anchor in zip(
            columns,
            headings,
            widths,
            resolved_anchors,
        ):
            tree.heading(column, text=heading)
            tree.column(column, width=width, minwidth=60, anchor=anchor)

        return frame, tree

    def _build_overview_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab, text="Overview")

        metrics = ttk.Frame(tab)
        metrics.pack(fill="x", pady=(0, 10))
        self.metric_vars: dict[str, tk.StringVar] = {}
        metric_definitions = (
            ("packets", "Packets"),
            ("endpoints", "IP endpoints"),
            ("bvlc", "BVLC"),
            ("npdu", "NPDU"),
            ("apdu", "APDU"),
            ("parsed", "Parsed"),
            ("problems", "Partial/Malformed/Error"),
        )

        for column, (key, label) in enumerate(metric_definitions):
            card = ttk.LabelFrame(metrics, text=label, padding=8)
            card.grid(row=0, column=column, sticky="nsew", padx=4)
            value = tk.StringVar(value="0")
            self.metric_vars[key] = value
            ttk.Label(card, textvariable=value, style="Metric.TLabel").pack()
            metrics.columnconfigure(column, weight=1)

        ttk.Label(tab, text="Imported captures", style="Heading.TLabel").pack(
            anchor="w",
            pady=(2, 6),
        )
        frame, self.capture_tree = self._tree_panel(
            tab,
            (
                "capture_id",
                "filename",
                "imported_at",
                "packet_count",
                "start",
                "end",
                "link_type",
                "notes",
            ),
            (
                "ID",
                "File",
                "Imported",
                "Packets",
                "Start",
                "End",
                "Link type",
                "Notes",
            ),
            (60, 260, 155, 80, 165, 165, 80, 260),
            anchors=("center", "w", "w", "e", "w", "w", "center", "w"),
        )
        frame.pack(fill="both", expand=True)
        self.capture_tree.bind("<Double-1>", self._select_capture_from_tree)

    def _build_devices_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="IP Devices")

        pane = ttk.Panedwindow(tab, orient="horizontal")
        pane.pack(fill="both", expand=True)

        device_frame, self.device_tree = self._tree_panel(
            pane,
            ("ip", "sent", "received", "total", "peers"),
            ("IP address", "Sent", "Received", "Total", "Peers"),
            (150, 65, 75, 65, 60),
            anchors=("w", "e", "e", "e", "e"),
        )
        pane.add(device_frame, weight=2)

        details = ttk.Frame(pane, padding=(8, 0, 0, 0))
        pane.add(details, weight=6)
        ttk.Label(
            details,
            textvariable=self.selected_device_var,
            style="Heading.TLabel",
        ).pack(anchor="w", pady=(0, 8))

        self.device_detail_notebook = ttk.Notebook(details)
        self.device_detail_notebook.pack(fill="both", expand=True)

        peers_tab = ttk.Frame(self.device_detail_notebook, padding=5)
        services_tab = ttk.Frame(self.device_detail_notebook, padding=5)
        self.device_detail_notebook.add(peers_tab, text="Communication peers")
        self.device_detail_notebook.add(services_tab, text="Services")

        peer_frame, self.peer_tree = self._tree_panel(
            peers_tab,
            ("peer", "sent", "received", "total", "services", "first", "last"),
            ("Peer", "Sent", "Received", "Total", "Services", "First", "Last"),
            (150, 70, 80, 70, 75, 155, 155),
            anchors=("w", "e", "e", "e", "e", "w", "w"),
        )
        peer_frame.pack(fill="both", expand=True)

        service_pane = ttk.Panedwindow(services_tab, orient="vertical")
        service_pane.pack(fill="both", expand=True)

        summary_area = ttk.LabelFrame(
            service_pane,
            text="Services observed for this endpoint",
            padding=5,
        )
        device_service_frame, self.device_service_tree = self._tree_panel(
            summary_area,
            (
                "family",
                "code",
                "name",
                "requests_sent",
                "requests_received",
                "responses_sent",
                "responses_received",
                "total",
            ),
            (
                "Family",
                "Code",
                "Service",
                "Req out",
                "Req in",
                "Resp out",
                "Resp in",
                "Total",
            ),
            (90, 55, 220, 70, 70, 75, 75, 65),
            anchors=("w", "e", "w", "e", "e", "e", "e", "e"),
            height=7,
        )
        device_service_frame.pack(fill="both", expand=True)
        service_pane.add(summary_area, weight=2)

        activity_area = ttk.LabelFrame(
            service_pane,
            text="Actual BACnet values and file data",
            padding=5,
        )
        activity_toolbar = ttk.Frame(activity_area)
        activity_toolbar.pack(fill="x", pady=(0, 5))
        ttk.Button(
            activity_toolbar,
            text="All values",
            command=self._show_all_device_read_writes,
        ).pack(side="right", padx=(8, 0))
        ttk.Label(
            activity_toolbar,
            textvariable=self.selected_device_service_var,
        ).pack(side="left", fill="x", expand=True)

        activity_frame, self.device_activity_tree = self._tree_panel(
            activity_area,
            ("operation", "target", "data"),
            ("Operation", "Target", "Actual value / data"),
            (190, 300, 520),
            anchors=("w", "w", "w"),
            height=12,
        )
        activity_frame.pack(fill="both", expand=True)
        service_pane.add(activity_area, weight=4)

        detail_area = ttk.LabelFrame(
            service_pane,
            text="Full selected value / data",
            padding=5,
        )
        self.device_activity_detail_text = tk.Text(
            detail_area,
            wrap="word",
            font=("TkFixedFont", 10),
            state="disabled",
            height=7,
        )
        detail_vertical = ttk.Scrollbar(
            detail_area,
            orient="vertical",
            command=self.device_activity_detail_text.yview,
        )
        self.device_activity_detail_text.configure(
            yscrollcommand=detail_vertical.set,
        )
        self.device_activity_detail_text.grid(row=0, column=0, sticky="nsew")
        detail_vertical.grid(row=0, column=1, sticky="ns")
        detail_area.rowconfigure(0, weight=1)
        detail_area.columnconfigure(0, weight=1)
        service_pane.add(detail_area, weight=2)

        self._bind_tree_selection(self.device_tree, self._device_selected)
        self._bind_tree_selection(
            self.device_service_tree,
            self._device_service_selected,
        )
        self._bind_tree_selection(
            self.device_activity_tree,
            self._device_activity_selected,
        )

    def _build_communications_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="Communications")
        frame, self.communication_tree = self._tree_panel(
            tab,
            ("source", "destination", "packets", "services", "first", "last"),
            ("Source IP", "Destination IP", "Packets", "Services", "First", "Last"),
            (180, 180, 85, 85, 175, 175),
            anchors=("w", "w", "e", "e", "w", "w"),
        )
        frame.pack(fill="both", expand=True)

    def _build_services_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="Services")

        pane = ttk.Panedwindow(tab, orient="horizontal")
        pane.pack(fill="both", expand=True)

        service_frame, self.service_tree = self._tree_panel(
            pane,
            ("family", "code", "name", "packets", "sources", "destinations", "first", "last"),
            ("Family", "Code", "Service", "Packets", "Sources", "Destinations", "First", "Last"),
            (105, 65, 250, 75, 75, 95, 155, 155),
            anchors=("w", "e", "w", "e", "e", "e", "w", "w"),
        )
        pane.add(service_frame, weight=4)

        endpoint_area = ttk.Frame(pane, padding=(8, 0, 0, 0))
        pane.add(endpoint_area, weight=3)
        ttk.Label(
            endpoint_area,
            textvariable=self.selected_service_var,
            style="Heading.TLabel",
        ).pack(anchor="w", pady=(0, 8))
        endpoint_frame, self.service_endpoint_tree = self._tree_panel(
            endpoint_area,
            ("ip", "sent", "received", "total", "first", "last"),
            ("IP address", "Sent", "Received", "Total", "First", "Last"),
            (150, 70, 80, 70, 155, 155),
            anchors=("w", "e", "e", "e", "w", "w"),
        )
        endpoint_frame.pack(fill="both", expand=True)
        self.service_tree.bind("<<TreeviewSelect>>", self._service_selected)

    def _build_packets_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(tab, text="Packets")

        filters = ttk.LabelFrame(tab, text="Filters", padding=8)
        filters.pack(fill="x", pady=(0, 8))

        ttk.Label(filters, text="Status:").grid(row=0, column=0, sticky="w")
        ttk.Combobox(
            filters,
            textvariable=self.packet_status_var,
            values=(ALL_STATUSES_LABEL,) + PACKET_STATUSES,
            state="readonly",
            width=16,
        ).grid(row=0, column=1, padx=(5, 14))

        ttk.Label(filters, text="IP endpoint:").grid(row=0, column=2, sticky="w")
        ttk.Entry(filters, textvariable=self.packet_device_var, width=20).grid(
            row=0,
            column=3,
            padx=(5, 14),
        )

        ttk.Label(filters, text="Service family:").grid(row=0, column=4, sticky="w")
        ttk.Combobox(
            filters,
            textvariable=self.packet_family_var,
            values=(ALL_SERVICE_FAMILIES_LABEL, "confirmed", "unconfirmed"),
            state="readonly",
            width=16,
        ).grid(row=0, column=5, padx=(5, 14))

        ttk.Label(filters, text="Service code:").grid(row=0, column=6, sticky="w")
        ttk.Entry(
            filters,
            textvariable=self.packet_service_code_var,
            width=9,
        ).grid(row=0, column=7, padx=(5, 14))

        ttk.Button(filters, text="Apply", command=self.refresh_packets).grid(
            row=0,
            column=8,
            padx=3,
        )
        ttk.Button(filters, text="Clear", command=self.clear_packet_filters).grid(
            row=0,
            column=9,
            padx=3,
        )

        pane = ttk.Panedwindow(tab, orient="vertical")
        pane.pack(fill="both", expand=True)

        packet_frame, self.packet_tree = self._tree_panel(
            pane,
            (
                "capture",
                "number",
                "timestamp",
                "status",
                "source",
                "destination",
                "ports",
                "bvlc",
                "apdu",
                "service",
            ),
            (
                "Capture",
                "Packet",
                "Timestamp",
                "Status",
                "Source",
                "Destination",
                "UDP ports",
                "BVLC function",
                "APDU type",
                "Service",
            ),
            (70, 70, 165, 90, 145, 145, 110, 225, 130, 220),
            anchors=("e", "e", "w", "w", "w", "w", "center", "w", "w", "w"),
            height=13,
        )
        pane.add(packet_frame, weight=3)

        detail_frame = ttk.LabelFrame(pane, text="Packet details", padding=5)
        self.packet_detail_text = tk.Text(
            detail_frame,
            wrap="none",
            font=("TkFixedFont", 10),
            state="disabled",
        )
        detail_vertical = ttk.Scrollbar(
            detail_frame,
            orient="vertical",
            command=self.packet_detail_text.yview,
        )
        detail_horizontal = ttk.Scrollbar(
            detail_frame,
            orient="horizontal",
            command=self.packet_detail_text.xview,
        )
        self.packet_detail_text.configure(
            yscrollcommand=detail_vertical.set,
            xscrollcommand=detail_horizontal.set,
        )
        self.packet_detail_text.grid(row=0, column=0, sticky="nsew")
        detail_vertical.grid(row=0, column=1, sticky="ns")
        detail_horizontal.grid(row=1, column=0, sticky="ew")
        detail_frame.rowconfigure(0, weight=1)
        detail_frame.columnconfigure(0, weight=1)
        pane.add(detail_frame, weight=2)

        for status in PACKET_STATUSES:
            self.packet_tree.tag_configure(status)
        self.packet_tree.bind("<<TreeviewSelect>>", self._packet_selected)

    @property
    def selected_capture_id(self) -> int | None:
        return self.capture_by_label.get(self.capture_var.get())

    @staticmethod
    def _timestamp(value: Any) -> str:
        if value is None:
            return ""
        try:
            return datetime.fromtimestamp(float(value)).astimezone().isoformat(
                sep=" ",
                timespec="seconds",
            )
        except (TypeError, ValueError, OSError, OverflowError):
            return str(value)

    @staticmethod
    def _clear_tree(tree: ttk.Treeview) -> None:
        children = tree.get_children()
        if children:
            tree.delete(*children)

    def _bind_tree_selection(
        self,
        tree: ttk.Treeview,
        callback: Any,
    ) -> None:
        """Run selection callbacks reliably for new and repeated clicks.

        Tk emits ``<<TreeviewSelect>>`` when the selection changes, but not
        when a user clicks an already-selected row.  The virtual event handles
        normal mouse/keyboard navigation; the deferred mouse callback handles
        repeated clicks after Tk has finished applying its class bindings.
        """

        def selection_changed(event: tk.Event[Any]) -> None:
            callback(event)

        def mouse_released(event: tk.Event[Any]) -> None:
            row_id = tree.identify_row(event.y)
            if not row_id:
                return

            def invoke_for_row() -> None:
                if not tree.exists(row_id):
                    return
                tree.selection_set(row_id)
                tree.focus(row_id)
                callback(None)

            self.root.after_idle(invoke_for_row)

        tree.bind("<<TreeviewSelect>>", selection_changed, add="+")
        tree.bind("<ButtonRelease-1>", mouse_released, add="+")

    def _set_detail_text(self, text: str) -> None:
        self.packet_detail_text.configure(state="normal")
        self.packet_detail_text.delete("1.0", "end")
        self.packet_detail_text.insert("1.0", text)
        self.packet_detail_text.configure(state="disabled")

    def _capture_changed(self, _event: tk.Event[Any] | None = None) -> None:
        self.refresh_views()

    def _select_capture_from_tree(self, _event: tk.Event[Any]) -> None:
        selection = self.capture_tree.selection()
        if not selection:
            return
        capture_id = int(selection[0])
        for label, mapped_id in self.capture_by_label.items():
            if mapped_id == capture_id:
                self.capture_var.set(label)
                self.refresh_views()
                break

    def refresh_all(self) -> None:
        try:
            previous_capture = self.selected_capture_id
            captures = self.repository.captures()
            self.capture_by_label = {ALL_CAPTURES_LABEL: None}
            labels = [ALL_CAPTURES_LABEL]

            for row in captures:
                label = f"{row['capture_id']}: {Path(row['filename']).name}"
                self.capture_by_label[label] = int(row["capture_id"])
                labels.append(label)

            self.capture_combo["values"] = labels
            chosen = ALL_CAPTURES_LABEL
            for label, capture_id in self.capture_by_label.items():
                if capture_id == previous_capture:
                    chosen = label
                    break
            self.capture_var.set(chosen)
            self._populate_capture_tree(captures)
            self.refresh_views()
            self.status_var.set(
                f"Loaded {len(captures)} capture(s) from {self.repository.path}"
            )
        except sqlite3.Error as error:
            self._show_database_error(error)

    def refresh_views(self) -> None:
        try:
            self.refresh_overview()
            self.refresh_devices()
            self.refresh_communications()
            self.refresh_services()
            self.refresh_packets()
        except sqlite3.Error as error:
            self._show_database_error(error)

    def _populate_capture_tree(self, captures: Iterable[sqlite3.Row]) -> None:
        self._clear_tree(self.capture_tree)
        for row in captures:
            self.capture_tree.insert(
                "",
                "end",
                iid=str(row["capture_id"]),
                values=(
                    row["capture_id"],
                    row["filename"],
                    row["imported_at"],
                    row["packet_count"] or 0,
                    self._timestamp(row["capture_start"]),
                    self._timestamp(row["capture_end"]),
                    "" if row["link_type"] is None else row["link_type"],
                    row["notes"] or "",
                ),
            )

    def refresh_overview(self) -> None:
        summary = self.repository.overview(self.selected_capture_id)
        statuses = summary.get("status_counts", {})
        problems = sum(
            int(statuses.get(status, 0))
            for status in ("partial", "malformed", "error")
        )
        values = {
            "packets": summary.get("packet_count") or 0,
            "endpoints": summary.get("endpoint_count") or 0,
            "bvlc": summary.get("bvlc_count") or 0,
            "npdu": summary.get("npdu_count") or 0,
            "apdu": summary.get("apdu_count") or 0,
            "parsed": statuses.get("parsed", 0),
            "problems": problems,
        }
        for key, value in values.items():
            self.metric_vars[key].set(f"{int(value):,}")

    def _set_device_activity_detail(self, text: str) -> None:
        self.device_activity_detail_text.configure(state="normal")
        self.device_activity_detail_text.delete("1.0", "end")
        self.device_activity_detail_text.insert("1.0", text)
        self.device_activity_detail_text.configure(state="disabled")

    def refresh_devices(self) -> None:
        self.selected_device_ip = None
        self.device_activity_rows.clear()
        self._clear_tree(self.device_tree)
        self._clear_tree(self.peer_tree)
        self._clear_tree(self.device_service_tree)
        self._clear_tree(self.device_activity_tree)
        self._set_device_activity_detail("")
        self.selected_device_var.set(
            "Select an IP endpoint to inspect its peers and services."
        )
        self.selected_device_service_var.set(
            "Select a read/write service, or show all actual values."
        )

        for row in self.repository.devices(self.selected_capture_id):
            ip_address = str(row["ip_address"])
            self.device_tree.insert(
                "",
                "end",
                iid=ip_address,
                values=(
                    ip_address,
                    row["sent_packets"],
                    row["received_packets"],
                    row["total_packets"],
                    row["peer_count"],
                ),
            )

    def _device_selected(self, _event: tk.Event[Any] | None) -> None:
        selection = self.device_tree.selection()
        if not selection:
            return

        ip_address = selection[0]
        self.selected_device_ip = ip_address
        self.selected_device_var.set(f"Endpoint: {ip_address}")
        self._clear_tree(self.peer_tree)
        self._clear_tree(self.device_service_tree)
        self._clear_tree(self.device_activity_tree)
        self.device_activity_rows.clear()
        self._set_device_activity_detail("")

        try:
            for row in self.repository.device_peers(
                ip_address,
                self.selected_capture_id,
            ):
                self.peer_tree.insert(
                    "",
                    "end",
                    values=(
                        row["peer_address"],
                        row["sent_packets"],
                        row["received_packets"],
                        row["total_packets"],
                        row["service_count"],
                        self._timestamp(row["first_seen"]),
                        self._timestamp(row["last_seen"]),
                    ),
                )

            for row in self.repository.device_services(
                ip_address,
                self.selected_capture_id,
            ):
                family = str(row["service_family"] or "")
                code = int(row["service_choice"])
                self.device_service_tree.insert(
                    "",
                    "end",
                    iid=f"{family}:{code}",
                    values=(
                        family,
                        code,
                        row["service_name"],
                        row["requests_sent"],
                        row["requests_received"],
                        row["responses_sent"],
                        row["responses_received"],
                        row["total_packets"],
                    ),
                )

            self._load_device_activity(read_write_only=True)

        except sqlite3.Error as error:
            self._show_database_error(error)

    def _show_all_device_read_writes(self) -> None:
        if self.selected_device_ip is None:
            return

        selection = self.device_service_tree.selection()
        if selection:
            self.device_service_tree.selection_remove(*selection)

        self._load_device_activity(read_write_only=True)

    def _device_service_selected(self, _event: tk.Event[Any] | None) -> None:
        if self.selected_device_ip is None:
            return

        selection = self.device_service_tree.selection()
        if not selection:
            return

        item = self.device_service_tree.item(selection[0])
        family = str(item["values"][0])
        code = int(item["values"][1])
        service_name = str(item["values"][2])

        if family != "confirmed" or code not in READ_WRITE_SERVICE_CHOICES:
            self._clear_tree(self.device_activity_tree)
            self.device_activity_rows.clear()
            message = (
                f"{service_name} does not carry a property or file value "
                "that this view displays."
            )
            self._set_device_activity_detail(message)
            self.selected_device_service_var.set(message)
            return

        self._load_device_activity(
            service_family=family,
            service_choice=code,
            label=f"Actual {service_name} values for {self.selected_device_ip}",
        )

    def _load_device_activity(
        self,
        *,
        service_family: str | None = None,
        service_choice: int | None = None,
        read_write_only: bool = False,
        label: str | None = None,
    ) -> None:
        """Load actual read results and write-request payloads for a device.

        Reads require a value-bearing response, so they are reconstructed from
        a request/response conversation. Writes are different: the value exists
        in the Confirmed-Request itself. A captured write request is therefore
        shown even when its ACK or Error response is missing. The direct packet
        fallback at the end also keeps unsegmented write requests visible when
        conversation matching cannot be completed.
        """
        if self.selected_device_ip is None:
            return

        self._clear_tree(self.device_activity_tree)
        self.device_activity_rows.clear()
        self._set_device_activity_detail("Loading values…")

        rows = self.repository.device_conversation_packets(
            self.selected_device_ip,
            self.selected_capture_id,
        )
        conversations = build_bacnet_conversations(
            rows,
            service_choices=sorted(READ_WRITE_SERVICE_CHOICES),
        )

        if service_family is not None and service_family != "confirmed":
            conversations = []
        if service_choice is not None:
            conversations = [
                conversation
                for conversation in conversations
                if conversation.service_choice == service_choice
            ]
        elif not read_write_only:
            conversations = []

        selected_rows: list[dict[str, Any]] = []
        for original_row in rows:
            row = dict(original_row)
            row_choice = row.get("service_choice")
            if row_choice is None:
                continue
            row_choice = int(row_choice)
            if row_choice not in READ_WRITE_SERVICE_CHOICES:
                continue
            if service_choice is not None and row_choice != service_choice:
                continue
            selected_rows.append(row)

        observed_write_requests = [
            row
            for row in selected_rows
            if int(row.get("pdu_type_code", -1)) == 0
            and int(row.get("service_choice", -1)) in WRITE_SERVICE_CHOICES
        ]
        observed_write_responses = [
            row
            for row in selected_rows
            if int(row.get("pdu_type_code", -1)) in (2, 3, 5)
            and int(row.get("service_choice", -1)) in WRITE_SERVICE_CHOICES
        ]

        actual_count = 0
        raw_fallback_count = 0
        incomplete_count = 0
        read_no_response_count = 0
        unacknowledged_write_count = 0
        response_only_write_count = 0
        empty_write_payload_count = 0
        represented_write_packet_ids: set[int] = set()

        for conversation in conversations:
            is_read = conversation.service_choice in READ_SERVICE_CHOICES
            is_write = conversation.service_choice in WRITE_SERVICE_CHOICES

            if is_read:
                if (
                    conversation.response is not None
                    and conversation.response.segmented
                    and not conversation.response.complete
                ):
                    incomplete_count += 1
                if conversation.status == "no-response":
                    read_no_response_count += 1
            elif is_write:
                if (
                    conversation.request is not None
                    and conversation.request.segmented
                    and not conversation.request.complete
                ):
                    incomplete_count += 1
                if conversation.status == "no-response":
                    unacknowledged_write_count += 1
                if conversation.request is None:
                    response_only_write_count += 1

            request_decoded: dict[str, Any] = {}
            response_decoded: dict[str, Any] = {}

            if conversation.request is not None and conversation.request.complete:
                request_decoded = decode_service_payload(
                    conversation.service_choice,
                    0,
                    conversation.request_payload,
                )

            response_pdu_type = conversation.response_pdu_type
            if (
                conversation.response is not None
                and conversation.response.complete
                and response_pdu_type is not None
            ):
                response_decoded = decode_service_payload(
                    conversation.service_choice,
                    response_pdu_type,
                    conversation.response_payload,
                )

            decoded = response_decoded if is_read else request_decoded
            source_assembly_complete = (
                conversation.response_complete
                if is_read
                else conversation.request_complete
            )

            # A write response (usually SimpleACK) never contains the value.
            # Without the corresponding request there is nothing truthful to
            # display in the actual-value table.
            if is_write and conversation.request is None:
                continue

            if not source_assembly_complete:
                continue

            decoded_items = list(decoded.get("items") or ())
            if not decoded_items and decoded.get("has_actual_data"):
                decoded_items = [dict(decoded)]

            # Complete write requests must remain visible even when a vendor
            # encoding or parser edge case prevents structured decoding. Keep
            # the entire service payload as a lossless fallback rather than
            # reporting zero writes.
            if is_write and not any(
                str(item.get("actual_data") or "")
                for item in decoded_items
            ):
                raw_payload = conversation.request_payload
                if raw_payload:
                    base_item: Mapping[str, Any] = {}
                    if decoded_items:
                        base_item = decoded_items[0]
                    elif request_decoded:
                        base_item = request_decoded

                    decoded_items = [
                        {
                            "operation": _service_operation_name(
                                conversation.service_choice
                            ),
                            "object": base_item.get("object", ""),
                            "property": base_item.get("property", ""),
                            "array_index": base_item.get("array_index", ""),
                            "target": base_item.get("target", ""),
                            "priority": base_item.get("priority", ""),
                            "actual_data": _raw_value_fallback(
                                raw_payload,
                                label=(
                                    "Undecoded complete write request"
                                ),
                            ),
                            "value": _raw_value_fallback(
                                raw_payload,
                                label=(
                                    "Undecoded complete write request"
                                ),
                            ),
                            "decode_quality": "raw-fallback",
                            "has_actual_data": True,
                        }
                    ]
                else:
                    empty_write_payload_count += 1
                    continue

            request_items = list(request_decoded.get("items") or ())
            if not request_items and request_decoded:
                request_items = [request_decoded]

            if is_read:
                if conversation.server_ip == self.selected_device_ip:
                    action = "Read from this device"
                    peer = conversation.client_ip
                else:
                    action = "Read by this device"
                    peer = conversation.server_ip
            else:
                if conversation.server_ip == self.selected_device_ip:
                    action = "Written to this device"
                    peer = conversation.client_ip
                else:
                    action = "Written by this device"
                    peer = conversation.server_ip

            emitted_for_conversation = False

            for item_index, original_item in enumerate(decoded_items):
                item = dict(original_item)

                # AtomicReadFile responses and some proprietary responses omit
                # target identity. Borrow only missing context from the request.
                request_item: Mapping[str, Any] = {}
                if request_items:
                    request_item = request_items[
                        min(item_index, len(request_items) - 1)
                    ]

                if is_read and request_item:
                    response_has_object = bool(item.get("object"))
                    for key in (
                        "object",
                        "property",
                        "array_index",
                        "priority",
                        "access_method",
                        "file_position",
                        "requested_count",
                    ):
                        if item.get(key) in (None, ""):
                            item[key] = request_item.get(key, "")

                    if not response_has_object and request_item.get("target"):
                        item["target"] = request_item["target"]
                    elif not item.get("target"):
                        item["target"] = request_item.get("target", "")

                actual_data = str(item.get("actual_data") or "")
                if not actual_data:
                    continue

                target = str(item.get("target") or item.get("object") or "")
                quality = str(item.get("decode_quality") or "decoded")
                row_id = (
                    f"conversation:{conversation.conversation_id}:"
                    f"value:{item_index}"
                )
                decorated = {
                    "conversation": conversation_summary(conversation),
                    "decoded": item,
                    "request_decoded": request_decoded,
                    "response_decoded": response_decoded,
                    "action": action,
                    "peer": peer,
                    "target": target,
                    "actual_data": actual_data,
                    "decode_quality": quality,
                }
                self.device_activity_rows[row_id] = decorated
                actual_count += 1
                emitted_for_conversation = True
                if quality == "raw-fallback":
                    raw_fallback_count += 1

                self.device_activity_tree.insert(
                    "",
                    "end",
                    iid=row_id,
                    values=(
                        action,
                        target,
                        _table_preview(actual_data),
                    ),
                )

            if is_write and emitted_for_conversation and conversation.request:
                represented_write_packet_ids.update(
                    conversation.request.packet_ids
                )

        # Defensive direct path for unsegmented writes. It avoids losing a real
        # write value if a capture starts mid-conversation, an invoke ID is
        # unusual, or conversation grouping fails for otherwise complete data.
        for row in observed_write_requests:
            packet_id_value = row.get("packet_id")
            packet_id = None if packet_id_value is None else int(packet_id_value)
            if packet_id is not None and packet_id in represented_write_packet_ids:
                continue
            if bool(row.get("segmented_message")):
                # Segments must only be decoded after safe reassembly.
                continue

            raw_value = row.get("raw_service_data")
            raw_payload = (
                b""
                if raw_value is None
                else bytes(raw_value)
            )
            if not raw_payload:
                empty_write_payload_count += 1
                continue

            row_service_choice = int(row["service_choice"])
            decoded = decode_service_payload(
                row_service_choice,
                0,
                raw_payload,
            )
            decoded_items = list(decoded.get("items") or ())
            if not decoded_items and decoded.get("has_actual_data"):
                decoded_items = [dict(decoded)]

            if not any(
                str(item.get("actual_data") or "")
                for item in decoded_items
            ):
                decoded_items = [
                    {
                        "operation": _service_operation_name(
                            row_service_choice
                        ),
                        "object": decoded.get("object", ""),
                        "property": decoded.get("property", ""),
                        "array_index": decoded.get("array_index", ""),
                        "target": decoded.get("target", ""),
                        "priority": decoded.get("priority", ""),
                        "actual_data": _raw_value_fallback(
                            raw_payload,
                            label="Undecoded complete write request",
                        ),
                        "value": _raw_value_fallback(
                            raw_payload,
                            label="Undecoded complete write request",
                        ),
                        "decode_quality": "raw-fallback",
                        "has_actual_data": True,
                    }
                ]

            source_ip = str(row.get("source_ip") or "")
            destination_ip = str(row.get("destination_ip") or "")
            if source_ip == self.selected_device_ip:
                action = "Written by this device"
                peer = destination_ip
            else:
                action = "Written to this device"
                peer = source_ip

            for item_index, original_item in enumerate(decoded_items):
                item = dict(original_item)
                actual_data = str(item.get("actual_data") or "")
                if not actual_data:
                    continue

                target = str(item.get("target") or item.get("object") or "")
                quality = str(item.get("decode_quality") or "decoded")
                identifier = (
                    str(packet_id)
                    if packet_id is not None
                    else f"row-{len(self.device_activity_rows)}"
                )
                row_id = f"packet:{identifier}:write:{item_index}"
                self.device_activity_rows[row_id] = {
                    "conversation": None,
                    "decoded": item,
                    "request_decoded": decoded,
                    "response_decoded": {},
                    "action": action,
                    "peer": peer,
                    "target": target,
                    "actual_data": actual_data,
                    "decode_quality": quality,
                    "packet": row,
                }
                actual_count += 1
                if quality == "raw-fallback":
                    raw_fallback_count += 1

                self.device_activity_tree.insert(
                    "",
                    "end",
                    iid=row_id,
                    values=(
                        action,
                        target,
                        _table_preview(actual_data),
                    ),
                )

        if label is None:
            label = f"Actual values read or written for {self.selected_device_ip}"

        notes: list[str] = [f"{actual_count:,} value(s)"]
        if raw_fallback_count:
            notes.append(
                f"{raw_fallback_count:,} preserved as raw BACnet data"
            )
        if incomplete_count:
            notes.append(
                f"{incomplete_count:,} incomplete segmented payload(s) hidden"
            )
        if read_no_response_count:
            notes.append(
                f"{read_no_response_count:,} read request(s) without a response"
            )
        if unacknowledged_write_count:
            notes.append(
                f"{unacknowledged_write_count:,} write request(s) without a captured ACK"
            )
        if response_only_write_count:
            notes.append(
                f"{response_only_write_count:,} write response(s) without a captured request"
            )
        if empty_write_payload_count:
            notes.append(
                f"{empty_write_payload_count:,} write request(s) had no stored payload"
            )

        self.selected_device_service_var.set(f"{label} — " + "; ".join(notes))

        children = self.device_activity_tree.get_children()
        if not children:
            selected_is_write = service_choice in WRITE_SERVICE_CHOICES
            selected_is_read = service_choice in READ_SERVICE_CHOICES

            if selected_is_write and not observed_write_requests and observed_write_responses:
                detail = (
                    "No write request payload was captured for this selection. "
                    f"The {len(observed_write_responses)} captured service packet(s) "
                    "are ACK/Error responses. A BACnet write response confirms or "
                    "rejects the operation but does not repeat the value that was "
                    "written; that value exists only in the original request."
                )
            elif selected_is_write and observed_write_requests:
                detail = (
                    "Write request packet(s) were captured, but no complete value "
                    "could be displayed. Check the status summary above for an "
                    "incomplete segmented request or an empty stored service payload."
                )
            elif selected_is_read:
                detail = (
                    "No returned read value was captured for this selection. "
                    "A read request identifies what was requested, but the actual "
                    "value exists in the matching ComplexACK response."
                )
            else:
                detail = (
                    "No captured read response or write request in this selection "
                    "contained a complete value payload."
                )

            self._set_device_activity_detail(detail)
            return

        first_item = children[0]
        self.device_activity_tree.selection_set(first_item)
        self.device_activity_tree.focus(first_item)
        self._show_device_activity_row(first_item)

    def _show_device_activity_row(self, row_id: str) -> None:
        """Display one selected value without relying on a queued Tk event."""
        activity = self.device_activity_rows.get(row_id)
        if activity is None:
            return

        actual_data = str(activity.get("actual_data") or "<empty>")
        self._set_device_activity_detail(actual_data)

    def _device_activity_selected(self, _event: tk.Event[Any] | None) -> None:
        selection = self.device_activity_tree.selection()
        row_id = selection[0] if selection else self.device_activity_tree.focus()

        if not row_id or row_id not in self.device_activity_rows:
            children = self.device_activity_tree.get_children()
            if not children:
                return
            row_id = children[0]
            self.device_activity_tree.selection_set(row_id)
            self.device_activity_tree.focus(row_id)

        self._show_device_activity_row(row_id)

    def refresh_communications(self) -> None:
        self._clear_tree(self.communication_tree)
        for row in self.repository.communications(self.selected_capture_id):
            self.communication_tree.insert(
                "",
                "end",
                values=(
                    row["source_ip"],
                    row["destination_ip"],
                    row["packet_count"],
                    row["service_count"],
                    self._timestamp(row["first_seen"]),
                    self._timestamp(row["last_seen"]),
                ),
            )

    def refresh_services(self) -> None:
        self._clear_tree(self.service_tree)
        self._clear_tree(self.service_endpoint_tree)
        self.selected_service_var.set(
            "Select a service to list participating endpoints."
        )
        for row in self.repository.services(self.selected_capture_id):
            family = str(row["service_family"] or "")
            code = int(row["service_choice"])
            iid = f"{family}:{code}"
            self.service_tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    family,
                    code,
                    row["service_name"],
                    row["packet_count"],
                    row["source_count"],
                    row["destination_count"],
                    self._timestamp(row["first_seen"]),
                    self._timestamp(row["last_seen"]),
                ),
            )

    def _service_selected(self, _event: tk.Event[Any]) -> None:
        selection = self.service_tree.selection()
        if not selection:
            return
        item = self.service_tree.item(selection[0])
        family = str(item["values"][0])
        code = int(item["values"][1])
        name = str(item["values"][2])
        self.selected_service_var.set(f"{family} {code}: {name}")
        self._clear_tree(self.service_endpoint_tree)

        try:
            rows = self.repository.service_endpoints(
                family,
                code,
                self.selected_capture_id,
            )
            for row in rows:
                self.service_endpoint_tree.insert(
                    "",
                    "end",
                    values=(
                        row["ip_address"],
                        row["sent_packets"],
                        row["received_packets"],
                        row["total_packets"],
                        self._timestamp(row["first_seen"]),
                        self._timestamp(row["last_seen"]),
                    ),
                )
        except sqlite3.Error as error:
            self._show_database_error(error)

    def _packet_filters(
        self,
    ) -> tuple[str | None, str | None, str | None, int | None]:
        status = self.packet_status_var.get()
        parse_status = None if status == ALL_STATUSES_LABEL else status

        device = self.packet_device_var.get().strip() or None

        family_value = self.packet_family_var.get()
        service_family = (
            None
            if family_value == ALL_SERVICE_FAMILIES_LABEL
            else family_value
        )

        code_text = self.packet_service_code_var.get().strip()
        service_choice: int | None = None
        if code_text:
            try:
                service_choice = int(code_text, 0)
            except ValueError as error:
                raise ValueError(
                    "Service code must be a decimal value or a value such as 0x0C."
                ) from error
            if not 0 <= service_choice <= 255:
                raise ValueError("Service code must be between 0 and 255.")

        return parse_status, device, service_family, service_choice

    def refresh_packets(self) -> None:
        try:
            parse_status, device, service_family, service_choice = (
                self._packet_filters()
            )
        except ValueError as error:
            messagebox.showerror("Invalid packet filter", str(error), parent=self.root)
            return

        self._clear_tree(self.packet_tree)
        self._set_detail_text("")

        try:
            total = self.repository.packet_count(
                capture_id=self.selected_capture_id,
                parse_status=parse_status,
                device=device,
                service_family=service_family,
                service_choice=service_choice,
            )
            rows = self.repository.packets(
                capture_id=self.selected_capture_id,
                parse_status=parse_status,
                device=device,
                service_family=service_family,
                service_choice=service_choice,
                limit=self.packet_limit,
            )
        except sqlite3.Error as error:
            self._show_database_error(error)
            return

        for row in rows:
            source_port = row["source_port"]
            destination_port = row["destination_port"]
            ports = ""
            if source_port is not None or destination_port is not None:
                ports = f"{source_port or ''} → {destination_port or ''}"

            service = ""
            if row["service_choice"] is not None:
                service = (
                    f"{row['service_family'] or ''} "
                    f"{row['service_choice']}: {row['service_name']}"
                ).strip()

            self.packet_tree.insert(
                "",
                "end",
                iid=str(row["packet_id"]),
                tags=(row["parse_status"],),
                values=(
                    row["capture_id"],
                    row["packet_number"],
                    self._timestamp(row["timestamp"]),
                    row["parse_status"],
                    row["source_ip"] or "",
                    row["destination_ip"] or "",
                    ports,
                    row["bvlc_function"] if row["bvlc_function"] != "Unknown BVLC Function" else "",
                    row["apdu_type"] if row["apdu_type"] != "Unknown APDU Type" else "",
                    service,
                ),
            )

        displayed = len(rows)
        suffix = ""
        if total > displayed:
            suffix = f" (showing first {displayed:,})"
        self.status_var.set(f"Packet filter matched {total:,} row(s){suffix}")

    def clear_packet_filters(self) -> None:
        self.packet_status_var.set(ALL_STATUSES_LABEL)
        self.packet_device_var.set("")
        self.packet_family_var.set(ALL_SERVICE_FAMILIES_LABEL)
        self.packet_service_code_var.set("")
        self.refresh_packets()

    def _packet_selected(self, _event: tk.Event[Any]) -> None:
        selection = self.packet_tree.selection()
        if not selection:
            return
        packet_id = int(selection[0])
        try:
            detail = self.repository.packet_detail(packet_id)
        except sqlite3.Error as error:
            self._show_database_error(error)
            return

        if detail is None:
            self._set_detail_text("Packet no longer exists.")
            return
        self._set_detail_text(format_dictionary(detail, max_bytes=96))

    def open_database(self) -> None:
        filename = filedialog.askopenfilename(
            parent=self.root,
            title="Open BACnet SQLite database",
            filetypes=(
                ("SQLite databases", "*.db *.sqlite *.sqlite3"),
                ("All files", "*"),
            ),
        )
        if not filename:
            return

        try:
            new_repository = BacnetRepository(filename)
        except DatabaseOpenError as error:
            messagebox.showerror("Unable to open database", str(error), parent=self.root)
            return

        old_repository = self.repository
        self.repository = new_repository
        self.database_var.set(str(new_repository.path))
        old_repository.close()
        self.capture_var.set(ALL_CAPTURES_LABEL)
        self.refresh_all()

    def _show_database_error(self, error: Exception) -> None:
        self.status_var.set(f"Database error: {error}")
        messagebox.showerror("Database error", str(error), parent=self.root)

    def close(self) -> None:
        try:
            self.repository.close()
        finally:
            self.root.destroy()


def check_database(database_path: str | Path) -> dict[str, Any]:
    """Validate a database and return a compact non-GUI summary."""
    repository = BacnetRepository(database_path)
    try:
        captures = repository.captures()
        overview = repository.overview(None)
        return {
            "database": str(repository.path),
            "capture_count": len(captures),
            "packet_count": overview.get("packet_count") or 0,
            "endpoint_count": overview.get("endpoint_count") or 0,
            "bvlc_count": overview.get("bvlc_count") or 0,
            "npdu_count": overview.get("npdu_count") or 0,
            "apdu_count": overview.get("apdu_count") or 0,
            "status_counts": overview.get("status_counts", {}),
        }
    finally:
        repository.close()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Browse the BACnet SQLite capture database.",
    )
    parser.add_argument(
        "--database",
        default=DEFAULT_DATABASE_PATH,
        help=f"SQLite database path (default: {DEFAULT_DATABASE_PATH})",
    )
    parser.add_argument(
        "--packet-limit",
        type=int,
        default=DEFAULT_PACKET_LIMIT,
        help=(
            "Maximum packet rows loaded into the packet table "
            f"(default: {DEFAULT_PACKET_LIMIT})"
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate the database and print a summary without opening Tkinter.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)

    if args.packet_limit <= 0:
        print("error: --packet-limit must be greater than zero", file=sys.stderr)
        return 2

    if args.check:
        try:
            summary = check_database(args.database)
        except DatabaseOpenError as error:
            print(f"error: {error}", file=sys.stderr)
            return 1

        print(format_dictionary(summary))
        return 0

    try:
        repository = BacnetRepository(args.database)
    except DatabaseOpenError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    try:
        root = tk.Tk()
    except tk.TclError as error:
        repository.close()
        print(f"error: unable to open Tkinter interface: {error}", file=sys.stderr)
        return 1

    BacnetBrowserApp(
        root,
        repository,
        packet_limit=args.packet_limit,
    )
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
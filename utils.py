"""Small display helpers for nested packet-parser records.

The parser produces dictionaries containing nested dictionaries, lists of
entries, raw byte strings, and optional values. These helpers render that
structure without dumping unreadable Python byte literals or failing on nested
lists.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping, Sequence, Set
from typing import Any, TextIO


DEFAULT_INDENT_STEP = 4
DEFAULT_MAX_BYTES = 64


def _format_bytes(value: bytes, max_bytes: int) -> str:
    """Return a compact hexadecimal representation of a byte string."""
    displayed = value[:max_bytes]
    hexadecimal = displayed.hex(" ")

    if len(value) > max_bytes:
        omitted = len(value) - max_bytes
        hexadecimal = f"{hexadecimal} ... <{omitted} more bytes>"

    if not hexadecimal:
        hexadecimal = "<empty>"

    return f"bytes[{len(value)}]: {hexadecimal}"


def _format_scalar(value: Any, max_bytes: int) -> str:
    """Format a non-container value for human-readable output."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _format_bytes(bytes(value), max_bytes)

    if isinstance(value, str):
        return value

    return repr(value)


def _is_sequence(value: Any) -> bool:
    """Return whether a value should be rendered as an indexed sequence."""
    return isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray, memoryview),
    )


def _render_value(
    value: Any,
    *,
    level: int,
    indent_step: int,
    max_bytes: int,
    active_containers: set[int],
) -> list[str]:
    """Recursively render one packet-record value into output lines."""
    indentation = " " * level

    is_mapping = isinstance(value, Mapping)
    is_sequence = _is_sequence(value)
    is_set = isinstance(value, Set) and not isinstance(
        value,
        (str, bytes, bytearray, memoryview),
    )

    if not (is_mapping or is_sequence or is_set):
        return [f"{indentation}{_format_scalar(value, max_bytes)}"]

    container_id = id(value)

    if container_id in active_containers:
        return [f"{indentation}<recursive reference>"]

    active_containers.add(container_id)

    try:
        if is_mapping:
            if not value:
                return [f"{indentation}{{}}"]

            lines: list[str] = []

            for key, child_value in value.items():
                key_text = str(key)

                child_is_container = (
                    isinstance(child_value, Mapping)
                    or _is_sequence(child_value)
                    or (
                        isinstance(child_value, Set)
                        and not isinstance(
                            child_value,
                            (str, bytes, bytearray, memoryview),
                        )
                    )
                )

                if child_is_container:
                    lines.append(f"{indentation}{key_text}:")

                    lines.extend(
                        _render_value(
                            child_value,
                            level=level + indent_step,
                            indent_step=indent_step,
                            max_bytes=max_bytes,
                            active_containers=active_containers,
                        )
                    )

                else:
                    formatted = _format_scalar(
                        child_value,
                        max_bytes,
                    )

                    lines.append(
                        f"{indentation}{key_text}: {formatted}"
                    )

            return lines

        if is_set:
            values = sorted(value, key=repr)
        else:
            values = list(value)

        if not values:
            empty_marker = "set()" if is_set else "[]"
            return [f"{indentation}{empty_marker}"]

        lines = []

        for index, child_value in enumerate(values):
            item_prefix = f"{indentation}[{index}]"

            child_is_container = (
                isinstance(child_value, Mapping)
                or _is_sequence(child_value)
                or (
                    isinstance(child_value, Set)
                    and not isinstance(
                        child_value,
                        (str, bytes, bytearray, memoryview),
                    )
                )
            )

            if child_is_container:
                lines.append(f"{item_prefix}:")

                lines.extend(
                    _render_value(
                        child_value,
                        level=level + indent_step,
                        indent_step=indent_step,
                        max_bytes=max_bytes,
                        active_containers=active_containers,
                    )
                )

            else:
                formatted = _format_scalar(
                    child_value,
                    max_bytes,
                )

                lines.append(f"{item_prefix}: {formatted}")

        return lines

    finally:
        active_containers.remove(container_id)


def format_dictionary(
    data: Mapping[str, Any],
    *,
    indent: int = 0,
    indent_step: int = DEFAULT_INDENT_STEP,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> str:
    """Return a readable multiline representation of a nested dictionary.

    Args:
        data: Packet or protocol-layer record to render.
        indent: Number of spaces before the top-level keys.
        indent_step: Number of spaces added for each nested level.
        max_bytes: Maximum number of bytes shown before truncating a byte
            string's hexadecimal representation.
    """
    if indent < 0:
        raise ValueError("indent must be zero or greater")

    if indent_step <= 0:
        raise ValueError("indent_step must be greater than zero")

    if max_bytes < 0:
        raise ValueError("max_bytes must be zero or greater")

    if not isinstance(data, Mapping):
        raise TypeError("data must be a mapping")

    return "\n".join(
        _render_value(
            data,
            level=indent,
            indent_step=indent_step,
            max_bytes=max_bytes,
            active_containers=set(),
        )
    )


def print_dictionary(
    data: Mapping[str, Any],
    *,
    indent: int = 0,
    indent_step: int = DEFAULT_INDENT_STEP,
    max_bytes: int = DEFAULT_MAX_BYTES,
    file: TextIO | None = None,
) -> None:
    """Print a readable nested dictionary to stdout or another text stream."""
    output_stream = sys.stdout if file is None else file

    print(
        format_dictionary(
            data,
            indent=indent,
            indent_step=indent_step,
            max_bytes=max_bytes,
        ),
        file=output_stream,
    )
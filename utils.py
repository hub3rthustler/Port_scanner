"""Helper functions for PortScanApp."""

from __future__ import annotations

import ipaddress


MIN_PORT = 1
MAX_PORT = 65_535


def validate_target(target: str) -> bool:
    """Return whether *target* is a valid IP address or DNS hostname.

    Name resolution is deliberately left to the scanner so validation never
    blocks the Tkinter event loop.
    """
    target = target.strip()
    if not target or len(target) > 253:
        return False

    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # A trailing dot is valid for a fully qualified DNS name.
    hostname = target[:-1] if target.endswith(".") else target
    if not hostname:
        return False

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return False

    if len(ascii_hostname) > 253:
        return False

    labels = ascii_hostname.split(".")
    if len(labels) > 1 and all(label.isdigit() for label in labels):
        return False
    return all(
        label
        and len(label) <= 63
        and label[0].isalnum()
        and label[-1].isalnum()
        and all(character.isalnum() or character == "-" for character in label)
        for label in labels
    )


def parse_port_range(port_input: str) -> list[int] | None:
    """Parse a comma-separated list of ports and inclusive port ranges.

    Examples include ``80``, ``20-80`` and ``22,80-100,443``. A sorted list
    of unique ports is returned, or ``None`` when the input is invalid.
    """
    if not port_input or not port_input.strip():
        return None

    ports: set[int] = set()
    segments = [segment.strip() for segment in port_input.split(",")]

    for segment in segments:
        if not segment:
            return None

        if "-" in segment:
            parts = segment.split("-")
            if len(parts) != 2:
                return None
            try:
                start, end = (int(part.strip()) for part in parts)
            except ValueError:
                return None

            if not (MIN_PORT <= start <= end <= MAX_PORT):
                return None
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(segment)
            except ValueError:
                return None

            if not MIN_PORT <= port <= MAX_PORT:
                return None
            ports.add(port)

    return sorted(ports) if ports else None


def format_port_count(ports: list[int]) -> str:
    """Return a human-readable English port count."""
    count = len(ports)
    return f"{count} port{'s' if count != 1 else ''}"

### utils.py
# Helper functions for PortScanApp

import socket
import re


def validate_target(target):
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        pass

    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z]{2,6}$'
    )
    if domain_regex.match(target):
        return True

    return False


def parse_port_range(port_input):
    """
    Parses port input into a sorted list of unique port numbers.

    Supported formats:
      - Single port:        "80"
      - Range:              "20-80"
      - Comma-separated:    "22,80,443"
      - Mixed:              "22,80-100,443,8080-8090"

    Returns a sorted list of ints, or None if input is invalid.
    """
    if not port_input or not port_input.strip():
        return None

    ports = set()

    segments = [s.strip() for s in port_input.split(',')]

    for segment in segments:
        if not segment:
            return None

        if '-' in segment:
            # Could be a range like "80-100"
            parts = segment.split('-')
            if len(parts) != 2:
                return None
            try:
                start, end = int(parts[0].strip()), int(parts[1].strip())
            except ValueError:
                return None

            if not (0 <= start <= 65535 and 0 <= end <= 65535):
                return None
            if start > end:
                return None

            ports.update(range(start, end + 1))
        else:
            # Single port
            try:
                port = int(segment)
            except ValueError:
                return None

            if not (0 <= port <= 65535):
                return None

            ports.add(port)

    if not ports:
        return None

    return sorted(ports)


def format_port_count(ports):
    """Returns a human-readable string with the port count."""
    n = len(ports)
    return f"{n} port{'s' if n != 1 else ''}"
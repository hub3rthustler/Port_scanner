"""Safe result exporters for PortScanApp."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from xml.etree import ElementTree


def _safe_csv_cell(value: object) -> object:
    """Prevent spreadsheet applications from interpreting data as a formula."""
    if not isinstance(value, str):
        return value
    stripped = value.lstrip()
    if stripped.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _safe_xml_text(value: str) -> str:
    """Remove characters forbidden by XML 1.0 while preserving normal text."""
    return "".join(
        character
        for character in value
        if character in "\t\n\r"
        or "\u0020" <= character <= "\ud7ff"
        or "\ue000" <= character <= "\ufffd"
    )


def export_results(filepath: str | Path, results: dict[int, str]) -> None:
    """Export scan results based on the destination file extension."""
    path = Path(filepath)
    suffix = path.suffix.lower()

    if suffix == ".json":
        with path.open("w", encoding="utf-8") as file:
            json.dump(results, file, indent=4, ensure_ascii=False, sort_keys=True)
            file.write("\n")
    elif suffix == ".csv":
        with path.open("w", encoding="utf-8", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["Port", "Banner"])
            for port, banner in sorted(results.items()):
                writer.writerow([port, _safe_csv_cell(banner)])
    elif suffix == ".xml":
        root = ElementTree.Element("scan_results")
        for port, banner in sorted(results.items()):
            element = ElementTree.SubElement(root, "port", number=str(port))
            element.text = _safe_xml_text(banner)
        ElementTree.ElementTree(root).write(
            path,
            encoding="utf-8",
            xml_declaration=True,
        )
    else:
        with path.open("w", encoding="utf-8", newline="\n") as file:
            file.write("Open Ports with Banners:\n")
            for port, banner in sorted(results.items()):
                file.write(f"Port {port} is open - Banner: {banner}\n")

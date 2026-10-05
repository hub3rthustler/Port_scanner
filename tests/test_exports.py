import csv
import json
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree

import exports


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary_directory.name)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_json_preserves_unicode(self):
        path = self.directory / "results.json"
        exports.export_results(path, {443: "Zażółć gęślą"})

        with path.open(encoding="utf-8") as file:
            self.assertEqual(json.load(file), {"443": "Zażółć gęślą"})

    def test_xml_escapes_markup_and_removes_invalid_control_characters(self):
        path = self.directory / "results.xml"
        exports.export_results(path, {80: "A&B <service>\x00"})

        root = ElementTree.parse(path).getroot()
        self.assertEqual(root.find("port").text, "A&B <service>")

    def test_csv_neutralizes_spreadsheet_formulas(self):
        path = self.directory / "results.csv"
        exports.export_results(path, {1234: "=HYPERLINK(\"https://example.test\")"})

        with path.open(encoding="utf-8", newline="") as file:
            rows = list(csv.reader(file))
        self.assertEqual(rows[1][1], "'=HYPERLINK(\"https://example.test\")")

    def test_plain_text_uses_utf8(self):
        path = self.directory / "results.txt"
        exports.export_results(path, {22: "SSH – usługa"})
        self.assertIn("SSH – usługa", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()


from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT / "service" / "common" / "src"))

from deepfence_common.http_parser import parse_http_request


class HttpParserTest(unittest.TestCase):
    def test_parse_plaintext_http_request_metadata(self) -> None:
        request = (
            "GET /search?q=%27%20OR%201%3D1 HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "User-Agent: sqlmap\r\n"
            "\r\n"
        )

        metadata = parse_http_request(request)

        self.assertIsNotNone(metadata)
        assert metadata is not None
        self.assertEqual(metadata.method, "GET")
        self.assertEqual(metadata.path, "/search")
        self.assertEqual(metadata.query, "q=' OR 1=1")
        self.assertEqual(metadata.host, "example.com")
        self.assertEqual(metadata.user_agent, "sqlmap")

    def test_non_http_payload_returns_none(self) -> None:
        self.assertIsNone(parse_http_request("\x16\x03\x01\x02\x00"))


if __name__ == "__main__":
    unittest.main()

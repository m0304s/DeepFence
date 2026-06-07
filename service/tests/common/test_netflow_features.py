from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT / "service" / "common" / "src"))

from deepfence_common.netflow_features import build_netflow_v1_features, tcp_flags_number


class NetFlowFeaturesTest(unittest.TestCase):
    def test_build_netflow_v1_features(self) -> None:
        features = build_netflow_v1_features(
            src_port=51515,
            dst_port=443,
            protocol="TCP",
            app_proto="tls",
            in_bytes=600,
            out_bytes=400,
            in_pkts=3,
            out_pkts=2,
            tcp_flags="18",
            duration_milliseconds=1000,
        )

        self.assertEqual(features["L4_SRC_PORT"], 51515.0)
        self.assertEqual(features["L4_DST_PORT"], 443.0)
        self.assertEqual(features["PROTOCOL"], 6.0)
        self.assertEqual(features["L7_PROTO"], 91.0)
        self.assertEqual(features["TCP_FLAGS"], 24.0)
        self.assertEqual(features["TOTAL_BYTES"], 1000.0)
        self.assertEqual(features["TOTAL_PKTS"], 5.0)
        self.assertEqual(features["BYTES_PER_PACKET"], 200.0)
        self.assertEqual(features["BYTES_PER_SECOND"], 1000.0)
        self.assertEqual(features["PACKETS_PER_SECOND"], 5.0)
        self.assertEqual(features["IN_OUT_BYTES_RATIO"], 1.5)
        self.assertEqual(features["IN_OUT_PKTS_RATIO"], 1.5)

    def test_tcp_flags_text_fallback(self) -> None:
        self.assertEqual(tcp_flags_number("SA"), 18.0)
        self.assertEqual(tcp_flags_number("syn,ack"), 18.0)


if __name__ == "__main__":
    unittest.main()

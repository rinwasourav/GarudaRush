"""
GarudaRush Automated Test Suite
================================
Unit and integration tests covering Flask API endpoints, ML predictor initialization,
feature extraction, and flow payload builders.
"""

import os
import unittest
from unittest.mock import MagicMock, patch
import json
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.model.ml_model import DDoSDetector, generate_dataset, FEATURE_COLUMNS
from src.server.server import app, _compute_threat
from src.agent.agent import calculate_entropy


class TestDDoSDetector(unittest.TestCase):
    def setUp(self):
        self.detector = DDoSDetector()

    def test_feature_extraction(self):
        flow = {
            "packet_rate": 100.0,
            "byte_rate": 5000.0,
            "syn_count": 10,
            "syn_ack_ratio": 1.0,
            "icmp_count": 0,
            "udp_count": 20,
            "tcp_count": 80,
            "fragment_count": 0,
            "http_requests": 5,
            "src_ip_entropy": 3.2,
            "top_destination_ports": {"80": 50, "443": 30}
        }
        features = self.detector.extract_features(flow)
        self.assertEqual(len(features), len(FEATURE_COLUMNS))
        self.assertEqual(features[0], 100.0)
        self.assertEqual(features[10], 2.0)

    def test_synthetic_generator(self):
        df = generate_dataset(n_normal=100, n_ddos=100)
        self.assertEqual(len(df), 200)
        self.assertIn("label", df.columns)
        for col in FEATURE_COLUMNS:
            self.assertIn(col, df.columns)

    def test_attack_classifier(self):
        features = [9000, 500000, 5000, 50, 0, 10, 8000, 0, 5, 1.1, 1]
        attack_type = DDoSDetector._classify_attack_type(features)
        self.assertEqual(attack_type, "syn_flood")


class TestAgentUtilities(unittest.TestCase):
    def test_calculate_entropy(self):
        counter = {"192.168.1.1": 10, "192.168.1.2": 10, "192.168.1.3": 10, "192.168.1.4": 10}
        entropy = calculate_entropy(counter)
        self.assertAlmostEqual(entropy, 2.0, places=2)

    def test_empty_entropy_sentinel(self):
        counter = {}
        entropy = calculate_entropy(counter)
        self.assertEqual(entropy, -1.0)


class TestServerEndpoints(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_health_endpoint(self):
        response = self.app.get("/api/health")
        self.assertIn(response.status_code, [200, 503])
        data = json.loads(response.data)
        self.assertIn("ml_model", data)

    def test_compute_threat(self):
        self.assertEqual(_compute_threat(60, 100), "critical")
        self.assertEqual(_compute_threat(30, 100), "high")
        self.assertEqual(_compute_threat(10, 100), "medium")
        self.assertEqual(_compute_threat(2, 100), "low")

    @patch("src.server.server.get_db")
    def test_flow_validation(self, mock_get_db):
        mock_flows = MagicMock()
        mock_get_db.return_value = (mock_flows, MagicMock(), MagicMock())

        # Invalid payload missing required fields (should return 400 Bad Request)
        response = self.app.post("/api/flow", json={"agent_id": "test"})
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()

"""API tests use small synthetic feature records, not real detection results."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.api import create_app
from backend.detection.anomaly_model import IsolationForestAnomalyModel
from backend.detection.feature_selection import OPTIONAL_FEATURES, REQUIRED_FEATURES


ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "artifacts" / "detection" / "isolation_forest.joblib"
FEATURE_NAMES = (*REQUIRED_FEATURES, *OPTIONAL_FEATURES)


def synthetic_records(count: int = 2) -> list[dict[str, float | str]]:
    records = []
    for index in range(count):
        record: dict[str, float | str] = {
            name: float((index + 1) * (column_index + 2))
            for column_index, name in enumerate(FEATURE_NAMES)
        }
        record.update(
            {
                "event_id": f"synthetic-event-{index}",
                "timestamp": f"2026-01-01T00:00:0{index}Z",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "source_port": 51515,
                "destination_port": 443,
                "Label": "Synthetic label must not be used",
            }
        )
        records.append(record)
    return records


class FlaskApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = IsolationForestAnomalyModel.load(MODEL_PATH)

    def setUp(self):
        self.app = create_app(model=self.model)
        self.app.testing = True
        self.client = self.app.test_client()

    def test_health_reports_actual_component_availability(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["components"]["model"]["available"])
        self.assertTrue(payload["components"]["temporal_correlation"]["available"])
        self.assertTrue(payload["components"]["knowledge_graph"]["available"])

    def test_analyze_returns_model_predictions_and_supported_summaries(self):
        records = synthetic_records()
        response = self.client.post("/api/analyze", json={"records": records})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(len(payload["predictions"]), len(records))
        for prediction in payload["predictions"]:
            self.assertEqual(
                set(("event_id", "anomaly_score", "is_anomaly", "model_version", "flow"))
                - set(prediction),
                set(),
            )
            self.assertNotIn("Label", prediction["flow"])
        self.assertIn("alerts", payload)
        self.assertIn("correlations", payload)
        self.assertIn("graph_statistics", payload)

    def test_alerts_correlations_and_graph_read_latest_real_analysis_state(self):
        self.client.post("/api/analyze", json={"records": synthetic_records()})
        alerts = self.client.get("/api/alerts")
        correlations = self.client.get("/api/correlations")
        graph = self.client.get("/api/graph")
        self.assertTrue(alerts.get_json()["analysis_available"])
        self.assertTrue(correlations.get_json()["analysis_available"])
        self.assertTrue(graph.get_json()["analysis_available"])
        self.assertIn("alerts", alerts.get_json())
        self.assertIn("skipped_rules", correlations.get_json())
        self.assertIn("nodes", graph.get_json()["graph"])
        self.assertIn("edges", graph.get_json()["graph"])
        json.dumps(graph.get_json())

    def test_empty_input_returns_empty_analysis_without_fake_results(self):
        response = self.client.post("/api/analyze", json={"records": []})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["predictions"], [])
        self.assertEqual(response.get_json()["alerts"], [])
        self.assertEqual(response.get_json()["correlations"], [])
        self.assertEqual(response.get_json()["graph_statistics"]["node_count"], 0)

    def test_missing_records_field_is_a_json_client_error(self):
        response = self.client.post("/api/analyze", json={"flows": []})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "invalid_request")

    def test_malformed_json_returns_consistent_json_error(self):
        response = self.client.post(
            "/api/analyze",
            data='{"records": [',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"]["code"], "bad_request")

    def test_non_json_content_type_returns_415(self):
        response = self.client.post("/api/analyze", data="records")
        self.assertEqual(response.status_code, 415)
        self.assertEqual(
            response.get_json()["error"]["code"],
            "unsupported_media_type",
        )

    def test_non_object_record_is_rejected(self):
        response = self.client.post("/api/analyze", json={"records": ["not-a-record"]})
        self.assertEqual(response.status_code, 400)

    def test_missing_fitted_features_returns_422_without_stack_trace(self):
        records = synthetic_records()
        for record in records:
            del record["Flow Duration"]
        response = self.client.post("/api/analyze", json={"records": records})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.get_json()["error"]["code"], "invalid_records")
        self.assertNotIn("Traceback", response.get_data(as_text=True))

    def test_unavailable_model_is_reported_in_health_and_analysis(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing = Path(temp_dir) / "missing.joblib"
            client = create_app(model_path=missing).test_client()
            health = client.get("/api/health")
            analysis = client.post(
                "/api/analyze",
                json={"records": synthetic_records(1)},
            )
        self.assertEqual(health.get_json()["status"], "degraded")
        self.assertFalse(health.get_json()["components"]["model"]["available"])
        self.assertEqual(analysis.status_code, 503)
        self.assertEqual(analysis.get_json()["error"]["code"], "model_unavailable")

    def test_unavailable_correlation_component_is_explicit(self):
        client = create_app(
            model=self.model,
            correlation_service=None,
        ).test_client()
        health = client.get("/api/health")
        analysis = client.post("/api/analyze", json={"records": synthetic_records(1)})
        self.assertEqual(health.get_json()["status"], "degraded")
        self.assertFalse(
            health.get_json()["components"]["temporal_correlation"]["available"]
        )
        self.assertEqual(analysis.status_code, 503)
        self.assertEqual(
            analysis.get_json()["error"]["code"],
            "correlation_unavailable",
        )

    def test_internal_processing_failure_returns_generic_500(self):
        with patch.object(self.model, "predict", side_effect=RuntimeError("sensitive path")):
            response = self.client.post(
                "/api/analyze",
                json={"records": synthetic_records(1)},
            )
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json()["error"]["code"], "analysis_failed")
        self.assertNotIn("sensitive path", response.get_data(as_text=True))
        self.assertNotIn("Traceback", response.get_data(as_text=True))

    def test_cors_headers_are_enabled_for_api(self):
        response = self.client.get("/api/health", headers={"Origin": "http://localhost:5500"})
        self.assertEqual(
            response.headers["Access-Control-Allow-Origin"],
            "http://localhost:5500",
        )


if __name__ == "__main__":
    unittest.main()

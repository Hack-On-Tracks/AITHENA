"""Unit tests use synthetic flow records; they are not dataset detections."""

import unittest
from datetime import datetime, timedelta, timezone

from backend.graph.correlation import (
    TemporalCorrelationConfig,
    TemporalCorrelationService,
)


BASE_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def synthetic_event(
    index,
    *,
    seconds=None,
    source_ip="192.0.2.10",
    destination_ip="198.51.100.20",
    destination_port=443,
    is_anomaly=True,
    byte_count=100,
    packet_count=2,
    **extra,
):
    event = {
        "timestamp": (BASE_TIME + timedelta(seconds=seconds if seconds is not None else index)).isoformat(),
        "event_id": f"synthetic-{index}",
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": "6",
        "is_anomaly": is_anomaly,
        "Fwd Packets Length Total": byte_count,
        "Bwd Packets Length Total": 0,
        "Total Fwd Packets": packet_count,
        "Total Backward Packets": 0,
        **extra,
    }
    return event


class TemporalCorrelationTests(unittest.TestCase):
    def test_empty_input_returns_empty_report(self):
        report = TemporalCorrelationService().correlate([])
        self.assertEqual(report.correlations, [])
        self.assertEqual(report.stats["records_received"], 0)
        self.assertIn("repeated_anomalies", report.skipped_rules)

    def test_one_anomaly_is_not_a_repeated_pattern(self):
        report = TemporalCorrelationService().correlate([synthetic_event(1)])
        self.assertEqual(report.correlations, [])

    def test_repeated_anomalies_in_window_are_correlated_and_aggregated(self):
        records = [
            synthetic_event(1, seconds=1, byte_count=100, packet_count=2),
            synthetic_event(2, seconds=5, byte_count=200, packet_count=3),
            synthetic_event(3, seconds=10, byte_count=300, packet_count=4),
        ]
        report = TemporalCorrelationService().correlate(records)
        finding = next(
            result for result in report.correlations
            if result["pattern"] == "repeated_anomalies"
        )
        self.assertEqual(finding["event_ids"], ["synthetic-1", "synthetic-2", "synthetic-3"])
        self.assertEqual(finding["event_count"], 3)
        self.assertEqual(finding["evidence"]["cumulative_bytes"], 600)
        self.assertEqual(finding["evidence"]["cumulative_packets"], 9)
        self.assertEqual(finding["evidence"]["time_gaps_seconds"], [4.0, 5.0])
        self.assertAlmostEqual(finding["evidence"]["event_frequency_per_second"], 1 / 3)
        self.assertEqual(finding["evidence_level"], "suspicious_pattern")
        self.assertFalse(finding["confirmed_attack"])

    def test_events_outside_window_do_not_correlate(self):
        records = [
            synthetic_event(1, seconds=0),
            synthetic_event(2, seconds=61),
            synthetic_event(3, seconds=122),
        ]
        report = TemporalCorrelationService().correlate(records)
        self.assertFalse(report.correlations)

    def test_events_are_sorted_by_timestamp_not_input_order(self):
        records = [
            synthetic_event(3, seconds=10),
            synthetic_event(1, seconds=1),
            synthetic_event(2, seconds=5),
        ]
        report = TemporalCorrelationService().correlate(records)
        finding = next(
            result for result in report.correlations
            if result["pattern"] == "repeated_anomalies"
        )
        self.assertEqual(
            finding["event_ids"],
            ["synthetic-1", "synthetic-2", "synthetic-3"],
        )

    def test_unrelated_sources_are_kept_in_separate_groups(self):
        records = [
            synthetic_event(1, source_ip="192.0.2.1"),
            synthetic_event(2, source_ip="192.0.2.1"),
            synthetic_event(3, source_ip="192.0.2.2"),
        ]
        report = TemporalCorrelationService().correlate(records)
        self.assertFalse(
            any(result["pattern"] == "repeated_anomalies" for result in report.correlations)
        )

    def test_missing_timestamp_skips_temporal_rules_safely(self):
        records = []
        for index in range(3):
            event = synthetic_event(index)
            del event["timestamp"]
            records.append(event)
        report = TemporalCorrelationService().correlate(records)
        self.assertFalse(report.correlations)
        self.assertEqual(report.stats["invalid_or_missing_timestamps"], 3)
        self.assertIn("valid timestamp", report.skipped_rules["repeated_anomalies"])

    def test_missing_identifiers_do_not_create_unrelated_group(self):
        records = [
            synthetic_event(index, source_ip=None, destination_ip=None)
            for index in range(3)
        ]
        report = TemporalCorrelationService().correlate(records)
        self.assertFalse(
            any(result["pattern"] == "repeated_anomalies" for result in report.correlations)
        )
        self.assertIn("identifier", report.skipped_rules["repeated_anomalies"])

    def test_missing_ports_skips_portscan_but_recurrence_can_still_run(self):
        records = []
        for index in range(3):
            event = synthetic_event(index, destination_port=None)
            del event["destination_port"]
            records.append(event)
        report = TemporalCorrelationService().correlate(records)
        self.assertTrue(
            any(result["pattern"] == "repeated_anomalies" for result in report.correlations)
        )
        self.assertIn("threshold", report.skipped_rules["port_scan_like"])

    def test_duplicate_event_id_is_dropped(self):
        event = synthetic_event(1, seconds=1)
        duplicate = dict(event)
        duplicate["is_anomaly"] = False
        report = TemporalCorrelationService().correlate([event, duplicate])
        self.assertEqual(report.stats["duplicate_records_dropped"], 1)
        self.assertEqual(report.stats["anomalous_records"], 1)
        self.assertFalse(report.correlations)

    def test_duplicate_without_event_id_uses_flow_fingerprint(self):
        event = synthetic_event(1)
        del event["event_id"]
        report = TemporalCorrelationService().correlate([event, dict(event)])
        self.assertEqual(report.stats["duplicate_records_dropped"], 1)

    def test_invalid_numeric_values_do_not_break_aggregation(self):
        records = [
            synthetic_event(1, byte_count="invalid", packet_count=float("inf")),
            synthetic_event(2, byte_count=-5, packet_count="invalid"),
            synthetic_event(3, byte_count=10, packet_count=1),
        ]
        report = TemporalCorrelationService().correlate(records)
        finding = next(
            result for result in report.correlations
            if result["pattern"] == "repeated_anomalies"
        )
        self.assertEqual(finding["evidence"]["cumulative_bytes"], 10)
        self.assertEqual(finding["evidence"]["byte_count_records"], 1)
        self.assertEqual(finding["evidence"]["cumulative_packets"], 1)
        self.assertEqual(finding["evidence"]["packet_count_records"], 1)

    def test_port_scan_like_rule_uses_configured_port_diversity(self):
        config = TemporalCorrelationConfig(
            portscan_min_distinct_destination_ports=3,
            portscan_min_distinct_destination_hosts=5,
        )
        records = [
            synthetic_event(index, destination_port=8000 + index)
            for index in range(3)
        ]
        report = TemporalCorrelationService(config).correlate(records)
        finding = next(
            result for result in report.correlations
            if result["pattern"] == "port_scan_like"
        )
        self.assertEqual(finding["evidence"]["distinct_destination_ports"], [8000, 8001, 8002])
        self.assertFalse(finding["confirmed_attack"])

    def test_ddos_like_rule_requires_multiple_sources_to_one_destination(self):
        config = TemporalCorrelationConfig(ddos_min_total_bytes=250)
        records = [
            synthetic_event(index, source_ip=f"192.0.2.{index + 1}")
            for index in range(3)
        ]
        report = TemporalCorrelationService(config).correlate(records)
        finding = next(
            result for result in report.correlations
            if result["pattern"] == "ddos_like"
        )
        self.assertEqual(finding["evidence"]["distinct_source_count"], 3)
        self.assertEqual(finding["destination_ips"], ["198.51.100.20"])
        self.assertEqual(finding["evidence"]["cumulative_bytes"], 300)

    def test_ddos_rule_is_disabled_without_volume_or_rate_threshold(self):
        records = [
            synthetic_event(index, source_ip=f"192.0.2.{index + 1}")
            for index in range(3)
        ]
        report = TemporalCorrelationService().correlate(records)
        self.assertNotIn(
            "ddos_like", [item["pattern"] for item in report.correlations]
        )
        self.assertIn("Disabled", report.skipped_rules["ddos_like"])

    def test_dos_like_requires_configured_volume_or_rate_evidence(self):
        config = TemporalCorrelationConfig(
            dos_min_total_bytes=500,
        )
        records = [
            synthetic_event(index, byte_count=200)
            for index in range(3)
        ]
        report = TemporalCorrelationService(config).correlate(records)
        finding = next(
            result for result in report.correlations if result["pattern"] == "dos_like"
        )
        self.assertEqual(finding["evidence"]["cumulative_bytes"], 600)

    def test_packet_rate_is_available_as_separate_configurable_evidence(self):
        config = TemporalCorrelationConfig(dos_min_packets_per_second=50)
        records = [
            synthetic_event(index, **{"Flow Packets/s": 100 + index})
            for index in range(3)
        ]
        report = TemporalCorrelationService(config).correlate(records)
        finding = next(
            result for result in report.correlations if result["pattern"] == "dos_like"
        )
        self.assertEqual(finding["evidence"]["peak_flow_packets_per_second"], 102)
        self.assertTrue(finding["evidence"]["packet_rate_threshold_matched"])

    def test_possible_exfil_requires_explicit_outbound_direction(self):
        config = TemporalCorrelationConfig(exfil_min_bytes=250)
        records_without_direction = [
            synthetic_event(index, byte_count=200)
            for index in range(3)
        ]
        skipped = TemporalCorrelationService(config).correlate(records_without_direction)
        self.assertIn("trusted direction", skipped.skipped_rules["possible_exfiltration"])
        records = [
            synthetic_event(index, byte_count=200, direction="egress")
            for index in range(3)
        ]
        report = TemporalCorrelationService(config).correlate(records)
        finding = next(
            result for result in report.correlations
            if result["pattern"] == "possible_exfiltration"
        )
        self.assertEqual(finding["evidence"]["outbound_bytes"], 600)
        self.assertIn("direction field", finding["evidence"]["direction_source"])

    def test_separate_detection_results_align_by_position(self):
        records = [
            synthetic_event(index, is_anomaly=False)
            for index in range(3)
        ]
        predictions = [
            {"event_id": f"synthetic-{index}", "is_anomaly": True, "anomaly_score": 0.4}
            for index in range(3)
        ]
        report = TemporalCorrelationService().correlate(records, predictions)
        self.assertTrue(
            any(result["pattern"] == "repeated_anomalies" for result in report.correlations)
        )

    def test_detection_result_event_id_must_match_corresponding_flow(self):
        records = [synthetic_event(1)]
        predictions = [{"event_id": "different-id", "is_anomaly": True}]
        with self.assertRaisesRegex(ValueError, "does not match"):
            TemporalCorrelationService().correlate(records, predictions)

    def test_ground_truth_label_does_not_drive_correlation(self):
        records = [
            synthetic_event(index, is_anomaly=False, Label="DDoS")
            for index in range(3)
        ]
        report = TemporalCorrelationService().correlate(records)
        self.assertEqual(report.correlations, [])
        self.assertEqual(report.stats["non_anomalous_records"], 3)

    def test_large_synthetic_input_uses_bounded_time_windows(self):
        records = [
            synthetic_event(index, seconds=index)
            for index in range(5000)
        ]
        report = TemporalCorrelationService().correlate(records)
        repeated = [
            item for item in report.correlations
            if item["pattern"] == "repeated_anomalies"
        ]
        self.assertGreater(len(repeated), 1)
        self.assertEqual(
            sum(item["event_count"] for item in repeated),
            5000,
        )

    def test_invalid_window_configuration_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "time_window_seconds"):
            TemporalCorrelationConfig(time_window_seconds=0)


if __name__ == "__main__":
    unittest.main()

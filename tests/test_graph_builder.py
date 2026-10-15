"""Graph builder tests use synthetic records, never real dataset detections."""

import json
import unittest

from backend.graph.graph_builder import (
    build_knowledge_graph,
    get_correlation_events,
    get_entity_relationships,
    get_neighbors,
    graph_statistics,
    graph_to_dict,
    update_knowledge_graph,
)


def synthetic_flow(event_id, **overrides):
    return {
        "event_id": event_id,
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "source_port": 51515,
        "destination_port": 443,
        "protocol": "6",
        "timestamp": "2026-01-01T00:00:00Z",
        "is_anomaly": True,
        "anomaly_score": 0.4,
        "model_version": "synthetic-model",
        **overrides,
    }


class KnowledgeGraphBuilderTests(unittest.TestCase):
    def test_empty_inputs_produce_empty_multidigraph(self):
        graph = build_knowledge_graph()
        self.assertEqual(graph_statistics(graph), {
            "node_count": 0,
            "edge_count": 0,
            "node_type_counts": {},
        })
        self.assertEqual(graph_to_dict(graph)["nodes"], [])

    def test_flow_links_available_source_and_destination_entities(self):
        graph = build_knowledge_graph([synthetic_flow("synthetic-flow-1")])
        flow_id = "flow:event_id:synthetic-flow-1"
        source_id = "entity:ip:192.0.2.10"
        destination_id = "entity:ip:198.51.100.20"
        self.assertEqual(graph.nodes[flow_id]["is_anomaly"], True)
        self.assertEqual(graph.edges[source_id, flow_id, "source_of"]["relationship"], "source_of")
        self.assertEqual(
            graph.edges[flow_id, destination_id, "destination_of"]["relationship"],
            "destination_of",
        )
        self.assertNotIn("Label", graph.nodes[flow_id])

    def test_multiple_flows_share_one_entity_node(self):
        graph = build_knowledge_graph(
            [
                synthetic_flow("synthetic-flow-1"),
                synthetic_flow("synthetic-flow-2", destination_ip="203.0.113.9"),
            ]
        )
        self.assertEqual(graph_statistics(graph)["node_type_counts"]["entity"], 3)
        self.assertEqual(
            len(get_neighbors(graph, "entity:ip:192.0.2.10")),
            2,
        )

    def test_correlation_connects_existing_events_by_event_and_record_references(self):
        graph = build_knowledge_graph(
            [
                synthetic_flow("synthetic-flow-1"),
                synthetic_flow(None, destination_ip="203.0.113.9"),
            ],
            correlation_results=[
                {
                    "correlation_id": "synthetic-corr-1",
                    "event_ids": ["synthetic-flow-1"],
                    "record_references": [{"record_index": 1}],
                    "pattern": "repeated_anomalies",
                    "evidence_level": "suspicious_pattern",
                    "confirmed_attack": False,
                    "source_ips": ["192.0.2.10"],
                    "destination_ips": [],
                    "device_ids": [],
                    "event_count": 2,
                }
            ],
        )
        events = get_correlation_events(graph, "synthetic-corr-1")
        self.assertEqual(
            [event["node_id"] for event in events],
            ["flow:event_id:synthetic-flow-1", "flow:record_index:1"],
        )
        self.assertFalse(graph.nodes["correlation:synthetic-corr-1"]["confirmed_attack"])

    def test_duplicate_event_id_is_represented_once(self):
        graph = build_knowledge_graph(
            [
                synthetic_flow("synthetic-flow-1"),
                synthetic_flow("synthetic-flow-1"),
            ]
        )
        self.assertEqual(
            sum(data["node_type"] == "flow" for _, data in graph.nodes(data=True)),
            1,
        )
        self.assertEqual(
            sum(data["relationship"] == "source_of" for *_, data in graph.edges(data=True)),
            1,
        )

    def test_missing_endpoint_identifiers_omit_entity_edges(self):
        graph = build_knowledge_graph(
            [synthetic_flow("synthetic-flow-1", source_ip=None, destination_ip=None)]
        )
        self.assertEqual(graph.number_of_nodes(), 1)
        self.assertEqual(graph.number_of_edges(), 0)

    def test_batch_record_reference_does_not_become_a_fabricated_event_id(self):
        graph = build_knowledge_graph([synthetic_flow(None)])
        flow = graph.nodes["flow:record_index:0"]
        self.assertEqual(flow["identity_type"], "record_reference")
        self.assertNotIn("event_id", flow)

    def test_relationship_query_reports_incoming_and_outgoing_edges(self):
        graph = build_knowledge_graph([synthetic_flow("synthetic-flow-1")])
        relationships = get_entity_relationships(graph, "flow:event_id:synthetic-flow-1")
        self.assertEqual(
            {(item["direction"], item["relationship"]) for item in relationships},
            {("incoming", "source_of"), ("outgoing", "destination_of")},
        )

    def test_update_mutates_and_returns_supplied_graph(self):
        graph = build_knowledge_graph()
        updated = update_knowledge_graph(graph, [synthetic_flow("synthetic-flow-1")])
        self.assertIs(updated, graph)
        self.assertEqual(graph_statistics(graph)["node_count"], 3)

    def test_graph_statistics_include_node_type_counts(self):
        graph = build_knowledge_graph(
            [synthetic_flow("synthetic-flow-1")],
            correlation_results=[
                {
                    "correlation_id": "synthetic-corr-1",
                    "event_ids": ["synthetic-flow-1"],
                    "record_references": [],
                    "source_ips": [],
                    "destination_ips": [],
                    "device_ids": [],
                }
            ],
        )
        self.assertEqual(
            graph_statistics(graph),
            {
                "node_count": 4,
                "edge_count": 3,
                "node_type_counts": {"correlation": 1, "entity": 2, "flow": 1},
            },
        )

    def test_serialized_graph_is_json_compatible_and_deterministic(self):
        records = [synthetic_flow("synthetic-flow-1")]
        first = graph_to_dict(build_knowledge_graph(records))
        second = graph_to_dict(build_knowledge_graph(records))
        self.assertEqual(first, second)
        self.assertEqual(json.loads(json.dumps(first)), first)

    def test_ground_truth_labels_are_not_copied_even_from_nested_evidence(self):
        graph = build_knowledge_graph(
            [synthetic_flow("synthetic-flow-1", Label="Synthetic attack label")],
            correlation_results=[
                {
                    "correlation_id": "synthetic-corr-1",
                    "event_ids": [],
                    "record_references": [],
                    "evidence": {
                        "observed": 1,
                        "Label": "Synthetic attack label",
                    },
                }
            ],
        )
        serialized = graph_to_dict(graph)
        self.assertNotIn("Label", json.dumps(serialized))

    def test_detection_results_align_and_do_not_overwrite_real_record_id_with_null(self):
        graph = build_knowledge_graph(
            [synthetic_flow("synthetic-flow-1")],
            detection_results=[
                {
                    "event_id": None,
                    "anomaly_score": 0.8,
                    "is_anomaly": True,
                    "model_version": "synthetic-model-v2",
                }
            ],
        )
        flow = graph.nodes["flow:event_id:synthetic-flow-1"]
        self.assertEqual(flow["event_id"], "synthetic-flow-1")
        self.assertEqual(flow["anomaly_score"], 0.8)
        self.assertEqual(flow["model_version"], "synthetic-model-v2")
        with self.assertRaisesRegex(ValueError, "align one-to-one"):
            build_knowledge_graph([synthetic_flow("synthetic-flow-1")], detection_results=[])

    def test_correlation_report_object_is_accepted(self):
        class SyntheticReport:
            correlations = [
                {
                    "correlation_id": "synthetic-corr-1",
                    "event_ids": [],
                    "record_references": [{"record_index": 0}],
                }
            ]

        graph = build_knowledge_graph(
            [synthetic_flow("synthetic-flow-1")],
            correlation_results=SyntheticReport(),
        )
        self.assertEqual(
            len(get_correlation_events(graph, "synthetic-corr-1")),
            1,
        )


if __name__ == "__main__":
    unittest.main()

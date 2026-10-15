"""NetworkX knowledge graph construction for flow detections and correlations."""

from __future__ import annotations

import json
import math
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import date, datetime
from numbers import Number
from typing import Any
from urllib.parse import quote

import networkx as nx


Graph = nx.MultiDiGraph
GRAPH_SCHEMA_VERSION = "1"
_FLOW_FIELDS = (
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "device_id",
    "protocol",
    "Protocol",
    "Flow Duration",
    "total_bytes",
    "total_packets",
    "Fwd Packets Length Total",
    "Bwd Packets Length Total",
    "Total Fwd Packets",
    "Total Backward Packets",
)
_DETECTION_FIELDS = (
    "event_id",
    "anomaly_score",
    "is_anomaly",
    "model_version",
)
_CORRELATION_FIELDS = (
    "start_timestamp",
    "end_timestamp",
    "event_count",
    "pattern",
    "matched_rule",
    "evidence_level",
    "confirmed_attack",
    "source_ips",
    "destination_ips",
    "source_ports",
    "destination_ports",
    "device_ids",
    "protocols",
    "evidence",
)


def _as_records(records: Iterable[Mapping[str, Any]] | Any) -> list[Mapping[str, Any]]:
    if callable(getattr(records, "to_dict", None)) and hasattr(records, "columns"):
        values = records.to_dict(orient="records")
    elif isinstance(records, Sequence):
        values = records
    else:
        values = list(records)
    if any(not isinstance(record, Mapping) for record in values):
        raise TypeError("Each input record must be a mapping.")
    return values


def _identifier(value: Any) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    if type(value).__name__ in {"NaTType", "NAType"}:
        return None
    if isinstance(value, Number):
        try:
            if not math.isfinite(float(value)):
                return None
        except (TypeError, ValueError, OverflowError):
            return None
    result = str(value).strip()
    return result or None


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {
            str(key): _json_value(item)
            for key, item in value.items()
            if str(key).casefold() != "label"
        }
    if isinstance(value, (list, tuple, set)):
        converted = [_json_value(item) for item in value]
        return sorted(converted, key=_sort_key) if isinstance(value, set) else converted
    item = getattr(value, "item", None)
    if callable(item):
        try:
            return _json_value(item())
        except (TypeError, ValueError, OverflowError):
            return str(value)
    return str(value)


def _sort_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _node_id(kind: str, identity: str) -> str:
    return f"{kind}:{quote(identity, safe='')}"


def _add_entity(graph: Graph, entity_type: str, identity: Any) -> str | None:
    value = _identifier(identity)
    if value is None:
        return None
    node_id = _node_id(f"entity:{entity_type}", value)
    graph.add_node(
        node_id,
        node_type="entity",
        entity_type=entity_type,
        identifier=value,
    )
    return node_id


def _add_relationship(
    graph: Graph,
    source: str,
    target: str,
    relationship: str,
) -> None:
    graph.add_edge(
        source,
        target,
        key=relationship,
        relationship=relationship,
    )


def _detection_results(
    detection_results: Sequence[Mapping[str, Any]] | None,
    row_count: int,
) -> list[Mapping[str, Any] | None]:
    if detection_results is None:
        return [None] * row_count
    if len(detection_results) != row_count:
        raise ValueError("detection_results must align one-to-one with flow_records.")
    if any(not isinstance(result, Mapping) for result in detection_results):
        raise TypeError("Each detection result must be a mapping.")
    return list(detection_results)


def _correlation_records(correlations: Any) -> list[Mapping[str, Any]]:
    if correlations is None:
        return []
    if hasattr(correlations, "correlations"):
        values = correlations.correlations
    elif isinstance(correlations, Mapping):
        values = correlations.get("correlations", [])
    else:
        values = correlations
    return _as_records(values)


def _flow_attributes(
    record: Mapping[str, Any],
    detection: Mapping[str, Any] | None,
    record_index: int,
    event_id: str | None,
) -> dict[str, Any]:
    attributes: dict[str, Any] = {
        "node_type": "flow",
        "identity_type": "event_id" if event_id is not None else "record_reference",
        "record_index": record_index,
    }
    for name in _FLOW_FIELDS:
        if name in record and name != "Label":
            value = _json_value(record[name])
            if value is not None:
                attributes[name] = value
    if "protocol" not in attributes and "Protocol" in attributes:
        attributes["protocol"] = attributes.pop("Protocol")
    for name in _DETECTION_FIELDS:
        if name in record and name != "event_id":
            attributes[name] = _json_value(record[name])
    if detection is not None:
        for name in _DETECTION_FIELDS:
            if name not in detection:
                continue
            value = detection[name]
            if name == "event_id" and _identifier(value) is None:
                continue
            attributes[name] = _json_value(value)
    if event_id is not None:
        attributes["event_id"] = event_id
    return attributes


def _create_flow_nodes(
    graph: Graph,
    records: Sequence[Mapping[str, Any]],
    detection_results: Sequence[Mapping[str, Any] | None],
) -> tuple[dict[int, str], dict[str, str]]:
    record_nodes: dict[int, str] = {}
    event_nodes: dict[str, str] = {}
    for index, record in enumerate(records):
        detection = detection_results[index]
        record_event_id = _identifier(record.get("event_id"))
        detection_event_id = (
            _identifier(detection.get("event_id"))
            if detection is not None
            else None
        )
        if (
            record_event_id is not None
            and detection_event_id is not None
            and record_event_id != detection_event_id
        ):
            raise ValueError(
                f"Detection result event_id does not match flow record at index {index}."
            )
        event_id = record_event_id or detection_event_id
        if event_id is not None and event_id in event_nodes:
            record_nodes[index] = event_nodes[event_id]
            continue
        node_id = (
            _node_id("flow:event_id", event_id)
            if event_id is not None
            else _node_id("flow:record_index", str(index))
        )
        graph.add_node(
            node_id,
            **_flow_attributes(record, detection, index, event_id),
        )
        record_nodes[index] = node_id
        if event_id is not None:
            event_nodes[event_id] = node_id

        for field, entity_type, relationship, reverse in (
            ("source_ip", "ip", "source_of", True),
            ("destination_ip", "ip", "destination_of", False),
            ("device_id", "device", "observed_on", True),
        ):
            entity_id = _add_entity(graph, entity_type, record.get(field))
            if entity_id is None:
                continue
            if reverse:
                _add_relationship(graph, entity_id, node_id, relationship)
            else:
                _add_relationship(graph, node_id, entity_id, relationship)
    return record_nodes, event_nodes


def _reference_indices(value: Any) -> list[int]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    indices: list[int] = []
    for reference in value:
        if not isinstance(reference, Mapping):
            continue
        index = reference.get("record_index")
        if isinstance(index, int) and not isinstance(index, bool) and index >= 0:
            indices.append(index)
    return indices


def _add_correlation_nodes(
    graph: Graph,
    correlations: Sequence[Mapping[str, Any]],
    record_nodes: Mapping[int, str],
    event_nodes: Mapping[str, str],
) -> None:
    for correlation in correlations:
        correlation_id = _identifier(correlation.get("correlation_id"))
        if correlation_id is None:
            continue
        node_id = _node_id("correlation", correlation_id)
        attributes = {
            "node_type": "correlation",
            "correlation_id": correlation_id,
        }
        for name in _CORRELATION_FIELDS:
            if name in correlation:
                attributes[name] = _json_value(correlation[name])
        graph.add_node(node_id, **attributes)

        linked_flows: set[str] = set()
        event_ids = correlation.get("event_ids", [])
        if isinstance(event_ids, Sequence) and not isinstance(event_ids, (str, bytes)):
            for event_id_value in event_ids:
                event_id = _identifier(event_id_value)
                if event_id is not None and event_id in event_nodes:
                    linked_flows.add(event_nodes[event_id])
        for index in _reference_indices(correlation.get("record_references")):
            flow_id = record_nodes.get(index)
            if flow_id is not None:
                linked_flows.add(flow_id)
        for flow_id in sorted(linked_flows):
            _add_relationship(graph, flow_id, node_id, "member_of")

        for field, entity_type in (
            ("source_ips", "ip"),
            ("destination_ips", "ip"),
            ("device_ids", "device"),
        ):
            values = correlation.get(field, [])
            if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
                continue
            for value in values:
                entity_id = _add_entity(graph, entity_type, value)
                if entity_id is not None:
                    _add_relationship(graph, entity_id, node_id, "participates_in")


def update_knowledge_graph(
    graph: Graph,
    flow_records: Iterable[Mapping[str, Any]] | Any = (),
    detection_results: Sequence[Mapping[str, Any]] | None = None,
    correlation_results: Any = None,
) -> Graph:
    """Add flow, detection, and correlation output to an existing graph."""
    if not isinstance(graph, nx.MultiDiGraph):
        raise TypeError("graph must be a NetworkX MultiDiGraph.")
    records = _as_records(flow_records)
    detections = _detection_results(detection_results, len(records))
    graph.graph["schema_version"] = GRAPH_SCHEMA_VERSION
    record_nodes, event_nodes = _create_flow_nodes(graph, records, detections)
    _add_correlation_nodes(
        graph,
        _correlation_records(correlation_results),
        record_nodes,
        event_nodes,
    )
    return graph


def build_knowledge_graph(
    flow_records: Iterable[Mapping[str, Any]] | Any = (),
    detection_results: Sequence[Mapping[str, Any]] | None = None,
    correlation_results: Any = None,
) -> Graph:
    """Build a directed multigraph from existing flow and detection outputs."""
    graph = nx.MultiDiGraph()
    return update_knowledge_graph(
        graph,
        flow_records,
        detection_results,
        correlation_results,
    )


def get_entity_relationships(graph: Graph, entity_id: str) -> list[dict[str, Any]]:
    """Return the incident edges and neighboring node attributes for a node."""
    if entity_id not in graph:
        raise KeyError(f"Graph node not found: {entity_id}")
    relationships: list[dict[str, Any]] = []
    for source, target, key, edge in graph.in_edges(entity_id, keys=True, data=True):
        relationships.append(
            {
                "direction": "incoming",
                "relationship": edge["relationship"],
                "neighbor_id": source,
                "neighbor": _json_value(dict(graph.nodes[source])),
                "edge": _json_value(dict(edge)),
                "edge_key": key,
            }
        )
    for source, target, key, edge in graph.out_edges(entity_id, keys=True, data=True):
        relationships.append(
            {
                "direction": "outgoing",
                "relationship": edge["relationship"],
                "neighbor_id": target,
                "neighbor": _json_value(dict(graph.nodes[target])),
                "edge": _json_value(dict(edge)),
                "edge_key": key,
            }
        )
    return sorted(
        relationships,
        key=lambda item: (
            item["direction"],
            item["relationship"],
            item["neighbor_id"],
            str(item["edge_key"]),
        ),
    )


def get_neighbors(graph: Graph, node_id: str) -> list[dict[str, Any]]:
    """Return unique neighboring nodes with their edge relationships."""
    neighbors: dict[str, dict[str, Any]] = {}
    for relationship in get_entity_relationships(graph, node_id):
        neighbor_id = relationship["neighbor_id"]
        entry = neighbors.setdefault(
            neighbor_id,
            {
                "node_id": neighbor_id,
                "node": relationship["neighbor"],
                "relationships": [],
            },
        )
        entry["relationships"].append(
            {
                "direction": relationship["direction"],
                "type": relationship["relationship"],
            }
        )
    return [neighbors[node_id] for node_id in sorted(neighbors)]


def get_correlation_events(graph: Graph, correlation_id: str) -> list[dict[str, Any]]:
    """Return flow nodes linked to a correlation group by member_of edges."""
    node_id = (
        correlation_id
        if correlation_id in graph
        else _node_id("correlation", correlation_id)
    )
    if node_id not in graph:
        raise KeyError(f"Correlation group not found: {correlation_id}")
    events = [
        {"node_id": source, "attributes": _json_value(dict(graph.nodes[source]))}
        for source, _, edge in graph.in_edges(node_id, data=True)
        if edge.get("relationship") == "member_of"
        and graph.nodes[source].get("node_type") == "flow"
    ]
    return sorted(events, key=lambda item: item["node_id"])


def graph_statistics(graph: Graph) -> dict[str, Any]:
    """Return basic counts and node-type totals."""
    counts = Counter(
        str(attributes.get("node_type", "unknown"))
        for _, attributes in graph.nodes(data=True)
    )
    return {
        "node_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges(),
        "node_type_counts": dict(sorted(counts.items())),
    }


def graph_to_dict(graph: Graph) -> dict[str, Any]:
    """Return deterministic JSON-serializable node-link graph data."""
    nodes = [
        {"id": node_id, **_json_value(dict(attributes))}
        for node_id, attributes in sorted(graph.nodes(data=True))
    ]
    edges = [
        {
            "source": source,
            "target": target,
            "key": str(key),
            **_json_value(dict(attributes)),
        }
        for source, target, key, attributes in graph.edges(keys=True, data=True)
    ]
    edges.sort(key=lambda item: (item["source"], item["target"], item["key"]))
    return {
        "schema_version": graph.graph.get("schema_version", GRAPH_SCHEMA_VERSION),
        "directed": True,
        "multigraph": True,
        "nodes": nodes,
        "edges": edges,
    }

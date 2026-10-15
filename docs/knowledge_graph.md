# LeakLens Network Knowledge Graph

## Scope and data sources

The graph builder consumes flow records, optional aligned Isolation Forest
detection results, and optional output from `TemporalCorrelationService`. It
does not load the raw Parquet dataset, train a model, create alerts, assign risk,
or confirm attacks. Ground-truth `Label` is never copied into the graph or used
to create evidence.

Inspection of all eight current Parquet files found 78 columns each, including
`Label`, and no timestamp, event ID, source/destination IP, port, device ID, or
other endpoint identity columns. Consequently, graph relationships based on
those identifiers are omitted for un-enriched dataset rows. The graph supports
these fields when a trusted ingestion layer supplies them.

## Graph schema

The graph is a directed NetworkX `MultiDiGraph`. Node IDs are namespaced and
URL-escaped to prevent collisions:

| Node type | ID form | Meaning |
| --- | --- | --- |
| `entity` | `entity:ip:<identifier>` | A supplied source/destination IP |
| `entity` | `entity:device:<identifier>` | A supplied device identifier |
| `flow` | `flow:event_id:<identifier>` | A flow with a supplied event ID |
| `flow` | `flow:record_index:<index>` | A flow addressed by its position in this input batch when no event ID exists |
| `correlation` | `correlation:<correlation_id>` | A supplied temporal correlation group |

The `record_index` form is explicitly batch-local, not a generated event ID;
it allows existing temporal `record_references` to point to the right flow.
Identical event IDs are represented once. Records without event IDs remain
distinct by input position because identical feature values alone cannot prove
that two flows are duplicates.

| Edge | Direction | Meaning |
| --- | --- | --- |
| `source_of` | source entity → flow | The supplied source identifier for a flow |
| `destination_of` | flow → destination entity | The supplied destination identifier for a flow |
| `observed_on` | device entity → flow | The supplied device associated with a flow |
| `member_of` | flow → correlation | The existing correlation output includes the flow |
| `participates_in` | entity → correlation | The existing correlation output reports the entity in its group |

Flow nodes include available endpoint/flow metadata and model output fields
(`event_id`, `anomaly_score`, `is_anomaly`, `model_version`). The score remains
an anomaly score, not a probability. Correlation nodes preserve selected
correlation evidence, timestamps, pattern, and the `confirmed_attack` field
from the correlation output. A graph edge is a relationship in supplied data,
not proof of malicious activity. Alerts/incidents are not included because
the backend has no corresponding record type.

## Public functions

- `build_knowledge_graph(flow_records=(), detection_results=None, correlation_results=None)`
  builds a fresh graph.
- `update_knowledge_graph(graph, ...)` adds records to an existing
  `MultiDiGraph`.
- `get_entity_relationships(graph, node_id)` returns ordered incoming and
  outgoing relationships and neighbor attributes.
- `get_neighbors(graph, node_id)` returns unique neighbors and relationship
  types.
- `get_correlation_events(graph, correlation_id)` returns flow nodes connected
  through `member_of`.
- `graph_statistics(graph)` returns node/edge totals and node-type counts.
- `graph_to_dict(graph)` returns deterministic, JSON-serializable node-link
  data.

Separate detection outputs must match the flow record count and align
positionally, as in the model's prediction output. Conflicting non-empty event
IDs are rejected. Correlation links are created only for event IDs or
`record_references` that resolve to flow records already present in the graph;
unknown references do not generate placeholder events.

## Limitations

The current dataset does not contain the identities needed to create
source/flow/destination paths. Without stable event IDs, flow node identities
are only stable within the same ordered batch. Temporal correlations produced
from the current raw dataset also cannot link events because trusted timestamps
and endpoint identifiers are absent. Ports and protocol, when supplied, are
stored as flow attributes rather than expanded into additional entity types.

## Tests

Synthetic unit tests are labeled in `tests/test_graph_builder.py`; they are
not real dataset detections. Run the new graph tests and existing graph-adjacent
backend tests from the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_graph_builder tests.test_temporal_correlation tests.test_anomaly_model
```

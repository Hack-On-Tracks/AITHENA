# LeakLens temporal correlation

## Current dataset and model facts

The inspected Parquet files contain numeric `Protocol`, `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`, `Fwd Packets Length Total`, `Bwd Packets Length Total`, `Flow Bytes/s`, `Flow Packets/s`, IAT statistics, and aggregate TCP flag counters. All eight files have the same column names.

The correlation module consumes `Protocol`, packet/byte totals, `Flow Bytes/s`, and `Flow Packets/s` where those fields are present. It does not use `Flow Duration`, IAT, or TCP flag counts: the first two have no event timestamps and their units are undocumented, and the aggregate flags alone do not establish a multi-event rule.

The inspected schema does **not** contain event timestamps, event IDs, source/destination IP addresses, source/destination ports, device IDs, or an explicit traffic direction. The existing Isolation Forest prediction shape is `event_id`, `anomaly_score`, `is_anomaly`, and `model_version`; on these dataset files the model returns `event_id: null`, because there is no event ID column.

There is currently no backend graph/correlation package or graph dependency. This module uses only the Python standard library and remains separate from feature selection, model training, and prediction.

## Input and output

`TemporalCorrelationService.correlate(flow_records, detection_results=None)` accepts an iterable of record mappings (or a pandas DataFrame). Records may contain flow fields and prediction fields together. Alternatively, pass model prediction results as a second argument; the two sequences must align one-to-one by position, and conflicting non-empty event IDs raise an error.

Canonical optional context keys are `timestamp`, `event_id`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `device_id`, `protocol`, and `direction`. Prediction keys are `is_anomaly`, `anomaly_score`, and `model_version`. Flow byte and packet aggregation recognizes the actual dataset column names:

- Bytes: `Fwd Packets Length Total` plus `Bwd Packets Length Total`; or an explicit `total_bytes`.
- Packets: `Total Fwd Packets` plus `Total Backward Packets`; or an explicit `total_packets`.
- Byte rate: `Flow Bytes/s`.
- Protocol: `Protocol` or canonical `protocol`.

The module never reads `Label`. Only a strict boolean `is_anomaly=True` can enter a correlation rule; a ground-truth class value alone cannot cause a finding. Valid timestamps are Python datetimes or ISO-8601 strings. Naive datetimes/strings are treated as UTC; numeric timestamps and date-only strings are rejected because their units/precision are ambiguous.

The result is a `CorrelationReport` with:

- `correlations`: findings with stable `correlation_id`, real `event_ids` when supplied, `record_references` containing input-batch row indexes, available endpoint identifiers, start/end time, event count, pattern, evidence, and matched rule.
- `stats`: input, deduplication, timestamp, and anomaly counts.
- `skipped_rules`: reasons that prevent or disable a rule for the input batch.

Every finding is marked `evidence_level: "suspicious_pattern"` and `confirmed_attack: false`. This stage does not assign a severity or risk score: the dataset does not establish suitable calibration, and flow statistics do not prove an attack.

## Algorithm and data quality behavior

1. Merge separately supplied model outputs by position after checking sequence lengths and event-ID consistency.
2. Deduplicate by non-empty event ID; when no ID is available, use a SHA-256 fingerprint of the relevant timestamp, identifiers, anomaly output, and flow count/rate fields. `Label` is excluded from this fingerprint.
3. Parse timestamps, retain only explicitly anomalous records with valid timestamps for temporal rules, and count records skipped for missing or invalid time/anomaly data.
4. Group events by the rule-specific source/device/destination key and protocol where applicable. Sort each group by timestamp, then use a two-pointer time-window sweep. To avoid emitting a finding for every overlapping rolling window, qualifying windows are emitted greedily as non-overlapping windows; a group that fails the minimum count advances by one event and is reconsidered.
5. Calculate recurrence, observed event frequency (`event_count / elapsed seconds between first and last event`; `null` for a single-timestamp event), inter-event gaps, cumulative byte/packet totals over valid values, and peak flow byte rate. Invalid, negative, or non-finite numeric values are excluded from the relevant aggregate, not replaced by zero. The output reports how many rows contributed to packet/byte sums.

Sorting costs O(n log n) across groups and the sweep is O(n) after sorting; processing stores the current input batch and grouped event references in memory. Exact duplicates without event IDs cannot always be distinguished from genuinely separate identical flows; provide real event IDs upstream where possible.

## Configurable thresholds

`TemporalCorrelationConfig` centralizes these starting settings:

| Setting | Default | Meaning |
|---|---:|---|
| `time_window_seconds` | 60 | Maximum span of a correlation window. |
| `min_repeated_anomalies` | 3 | Minimum anomalous records for recurrence, DoS, DDoS, and port-scan windows. |
| `dos_min_total_bytes` | `None` | Optional cumulative bytes needed to emit a DoS-like finding. |
| `dos_min_bytes_per_second` | `None` | Optional peak `Flow Bytes/s` threshold for a DoS-like finding. |
| `dos_min_packets_per_second` | `None` | Optional peak `Flow Packets/s` threshold for a DoS-like finding. |
| `ddos_min_total_bytes` | `None` | Optional cumulative bytes required for a DDoS-like finding. |
| `ddos_min_bytes_per_second` | `None` | Optional peak flow byte rate required for a DDoS-like finding. |
| `ddos_min_packets_per_second` | `None` | Optional peak flow packet rate required for a DDoS-like finding. |
| `ddos_min_distinct_sources` | 3 | Distinct `source_ip` count to emit a DDoS-like finding to one destination. |
| `portscan_min_distinct_destination_ports` | 10 | Port diversity needed for a port-scan-like finding. |
| `portscan_min_distinct_destination_hosts` | 10 | Destination-host diversity alternative for a port-scan-like finding. |
| `exfil_min_bytes` | `None` | Cumulative bytes needed for a possible exfiltration finding. |
| `outbound_direction_values` | `outbound`, `egress`, `outgoing` | Explicit `direction` values treated as outbound. Deployment must validate that field's meaning. |

Count defaults are configurable heuristics, not tuned thresholds or performance claims. DoS-like, DDoS-like, and exfiltration rules are disabled by default until their units and deployment-specific thresholds are verified. No rate is derived from `Flow Duration`, whose units are undocumented.

## Suspicious-pattern rules

| Pattern | Evidence required | Behavior with current dataset |
|---|---|---|
| Repeated anomalies | At least the configured anomaly count, valid timestamps, and a common `source_ip`, `device_id`, or fallback `destination_ip` (protocol is kept separate). | Skipped: timestamps and identifiers are absent. |
| DoS-like | Repeated anomalous flows grouped by destination, source, or device, plus configured cumulative-byte, peak-byte-rate, or peak-packet-rate evidence. | Disabled by default; additionally skipped on this dataset because timestamps and endpoint identifiers are absent. |
| DDoS-like | Repeated anomalous flows in one time window to the same destination from at least the configured number of distinct source IPs, plus configured byte-volume, peak-byte-rate, or peak-packet-rate evidence. | Disabled until a volume/rate threshold is configured; additionally skipped on this dataset because timestamps and both endpoint IPs are absent. |
| Port-scan-like | Repeated anomalous flows from one source/device spanning the configured number of distinct destination ports or destination hosts. | Skipped: timestamps, source IDs, ports, and destination IPs are absent. |
| Possible exfiltration | Explicitly outbound/egress direction, source/device grouping, valid timestamps, and cumulative bytes meeting the configured threshold. | Disabled by default and skipped: direction, timestamps, endpoint identity, and outbound context are absent. Forward/backward byte fields alone do not establish egress. |

These names describe patterns consistent with suspicious activity, not confirmed attack types. A single high-volume flow remains an anomaly-level observation; it does not establish DoS or exfiltration. No rule uses the dataset's attack labels as detection evidence.

## Tests and integration

Run the unit tests from the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_temporal_correlation -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

All records in `tests/test_temporal_correlation.py` are small synthetic unit-test fixtures. They are not detections on the real dataset and do not indicate real-world performance.

The next integration step is for the flow-ingestion/API layer to attach trustworthy timestamps, stable event IDs, endpoint/device identifiers, ports, and—if available—validated traffic direction to each flow, then pass a flow batch and its aligned `IsolationForestAnomalyModel.predict()` results to this service. The current dataset alone can be scored by the model but cannot produce valid multi-event temporal correlations.

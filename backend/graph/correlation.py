"""Time-window correlation for anomalous flow records with optional context."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from math import isfinite
from numbers import Number
from typing import Any


@dataclass(frozen=True)
class TemporalCorrelationConfig:
    """Configurable correlation windows and uncalibrated rule thresholds."""

    time_window_seconds: float = 60.0
    min_repeated_anomalies: int = 3
    dos_min_total_bytes: float | None = None
    dos_min_bytes_per_second: float | None = None
    dos_min_packets_per_second: float | None = None
    ddos_min_total_bytes: float | None = None
    ddos_min_bytes_per_second: float | None = None
    ddos_min_packets_per_second: float | None = None
    ddos_min_distinct_sources: int = 3
    portscan_min_distinct_destination_ports: int = 10
    portscan_min_distinct_destination_hosts: int = 10
    exfil_min_bytes: float | None = None
    outbound_direction_values: tuple[str, ...] = ("outbound", "egress", "outgoing")

    def __post_init__(self) -> None:
        if not isfinite(self.time_window_seconds) or self.time_window_seconds <= 0:
            raise ValueError("time_window_seconds must be a finite positive value.")
        if self.min_repeated_anomalies < 2:
            raise ValueError("min_repeated_anomalies must be at least 2.")
        if self.ddos_min_distinct_sources < 2:
            raise ValueError("ddos_min_distinct_sources must be at least 2.")
        if self.portscan_min_distinct_destination_ports < 2:
            raise ValueError("portscan port threshold must be at least 2.")
        if self.portscan_min_distinct_destination_hosts < 2:
            raise ValueError("portscan host threshold must be at least 2.")
        for name, threshold in (
            ("dos_min_total_bytes", self.dos_min_total_bytes),
            ("dos_min_bytes_per_second", self.dos_min_bytes_per_second),
            ("dos_min_packets_per_second", self.dos_min_packets_per_second),
            ("ddos_min_total_bytes", self.ddos_min_total_bytes),
            ("ddos_min_bytes_per_second", self.ddos_min_bytes_per_second),
            ("ddos_min_packets_per_second", self.ddos_min_packets_per_second),
            ("exfil_min_bytes", self.exfil_min_bytes),
        ):
            if threshold is not None and (
                not isfinite(threshold) or threshold <= 0
            ):
                raise ValueError(f"{name} must be finite and positive when configured.")
        if not self.outbound_direction_values or any(
            not value.strip() for value in self.outbound_direction_values
        ):
            raise ValueError("outbound_direction_values must contain non-empty values.")


@dataclass(frozen=True)
class CorrelationReport:
    """Correlation findings and transparent diagnostics for one input batch."""

    correlations: list[dict[str, Any]]
    stats: dict[str, Any]
    skipped_rules: dict[str, str]


@dataclass(frozen=True)
class _Event:
    input_index: int
    event_id: Any
    timestamp: datetime | None
    is_anomaly: bool
    anomaly_score: float | None
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None
    device_id: str | None
    direction: str | None
    byte_count: float | None
    packet_count: float | None
    byte_rate: float | None
    packet_rate: float | None
    fingerprint: str


def _as_records(records: Iterable[Mapping[str, Any]] | Any) -> list[Mapping[str, Any]]:
    if callable(getattr(records, "to_dict", None)) and hasattr(records, "columns"):
        values = records.to_dict(orient="records")
    elif isinstance(records, Sequence):
        values = records
    else:
        values = list(records)
    if any(not isinstance(record, Mapping) for record in values):
        raise TypeError("Each flow record must be a mapping.")
    return values


def _parse_timestamp(value: Any) -> datetime | None:
    if value is not None and type(value).__name__ in {"NaTType", "NAType"}:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text or ("T" not in text and " " not in text):
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _identifier(value: Any) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    if type(value).__name__ in {"NaTType", "NAType"}:
        return None
    if isinstance(value, Number):
        try:
            if not isfinite(float(value)):
                return None
        except (TypeError, ValueError, OverflowError):
            return None
    if isinstance(value, str):
        result = value.strip()
    else:
        result = str(value).strip()
    return result or None


def _finite_nonnegative(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not isfinite(numeric) or numeric < 0:
        return None
    return numeric


def _integer_port(value: Any) -> int | None:
    numeric = _finite_nonnegative(value)
    if numeric is None or not numeric.is_integer() or numeric > 65535:
        return None
    return int(numeric)


def _scalar_for_fingerprint(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


_FINGERPRINT_FIELDS = (
    "timestamp",
    "event_id",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "device_id",
    "protocol",
    "Protocol",
    "direction",
    "is_anomaly",
    "anomaly_score",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packets Length Total",
    "Bwd Packets Length Total",
    "total_bytes",
    "total_packets",
)


def _fingerprint(record: Mapping[str, Any]) -> str:
    canonical = {
        name: _scalar_for_fingerprint(record[name])
        for name in _FINGERPRINT_FIELDS
        if name in record
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _numeric_pair_sum(record: Mapping[str, Any], first: str, second: str) -> float | None:
    left = _finite_nonnegative(record.get(first))
    right = _finite_nonnegative(record.get(second))
    if left is None or right is None:
        return None
    return left + right


def _event_from_record(
    record: Mapping[str, Any], input_index: int, fingerprint: str
) -> _Event:
    total_bytes = _finite_nonnegative(record.get("total_bytes"))
    if total_bytes is None:
        total_bytes = _numeric_pair_sum(
            record, "Fwd Packets Length Total", "Bwd Packets Length Total"
        )
    total_packets = _finite_nonnegative(record.get("total_packets"))
    if total_packets is None:
        total_packets = _numeric_pair_sum(
            record, "Total Fwd Packets", "Total Backward Packets"
        )
    flag = record.get("is_anomaly")
    is_anomaly = flag if isinstance(flag, bool) else False
    score = _finite_signed(record.get("anomaly_score"))
    return _Event(
        input_index=input_index,
        event_id=record.get("event_id"),
        timestamp=_parse_timestamp(record.get("timestamp")),
        is_anomaly=is_anomaly,
        anomaly_score=score,
        source_ip=_identifier(record.get("source_ip")),
        destination_ip=_identifier(record.get("destination_ip")),
        source_port=_integer_port(record.get("source_port")),
        destination_port=_integer_port(record.get("destination_port")),
        protocol=_identifier(record.get("protocol") if "protocol" in record else record.get("Protocol")),
        device_id=_identifier(record.get("device_id")),
        direction=_identifier(record.get("direction")),
        byte_count=total_bytes,
        packet_count=total_packets,
        byte_rate=_finite_nonnegative(record.get("Flow Bytes/s")),
        packet_rate=_finite_nonnegative(record.get("Flow Packets/s")),
        fingerprint=fingerprint,
    )


def _finite_signed(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return numeric if isfinite(numeric) else None


def _recurrence_key(event: _Event) -> tuple[str, str, str] | None:
    protocol = event.protocol or ""
    if event.source_ip is not None:
        return "source_ip", event.source_ip, protocol
    if event.device_id is not None:
        return "device_id", event.device_id, protocol
    if event.destination_ip is not None:
        return "destination_ip", event.destination_ip, protocol
    return None


def _groups(
    events: Sequence[_Event],
    key_function: Any,
) -> dict[tuple[str, ...], list[_Event]]:
    grouped: dict[tuple[str, ...], list[_Event]] = defaultdict(list)
    for event in events:
        key = key_function(event)
        if key is not None:
            grouped[key].append(event)
    for values in grouped.values():
        values.sort(key=lambda event: (event.timestamp, event.input_index))
    return grouped


def _time_windows(
    grouped: Mapping[tuple[str, ...], Sequence[_Event]],
    window_seconds: float,
    minimum_events: int,
) -> Iterable[tuple[tuple[str, ...], list[_Event]]]:
    window = timedelta(seconds=window_seconds)
    for key in sorted(grouped):
        events = grouped[key]
        start = 0
        while start < len(events):
            end = start + 1
            cutoff = events[start].timestamp + window
            while end < len(events) and events[end].timestamp <= cutoff:
                end += 1
            if end - start >= minimum_events:
                yield key, list(events[start:end])
                start = end
            else:
                start += 1


def _metrics(events: Sequence[_Event], window_seconds: float) -> dict[str, Any]:
    timestamps = [event.timestamp for event in events]
    gaps = [
        (timestamps[index] - timestamps[index - 1]).total_seconds()
        for index in range(1, len(timestamps))
    ]
    known_bytes = [event.byte_count for event in events if event.byte_count is not None]
    known_packets = [
        event.packet_count for event in events if event.packet_count is not None
    ]
    observed_span = (timestamps[-1] - timestamps[0]).total_seconds()
    return {
        "event_frequency_per_second": (
            len(events) / observed_span if observed_span > 0 else None
        ),
        "recurrence_count": max(0, len(events) - 1),
        "configured_window_seconds": window_seconds,
        "observed_span_seconds": observed_span,
        "time_gaps_seconds": gaps,
        "cumulative_bytes": sum(known_bytes) if known_bytes else None,
        "byte_count_records": len(known_bytes),
        "cumulative_packets": sum(known_packets) if known_packets else None,
        "packet_count_records": len(known_packets),
        "peak_flow_bytes_per_second": max(
            (event.byte_rate for event in events if event.byte_rate is not None),
            default=None,
        ),
        "peak_flow_packets_per_second": max(
            (event.packet_rate for event in events if event.packet_rate is not None),
            default=None,
        ),
    }


def _unique_values(events: Sequence[_Event], attribute: str) -> list[Any]:
    return sorted(
        {value for event in events if (value := getattr(event, attribute)) is not None}
    )


def _correlation(
    pattern: str,
    matched_rule: str,
    key: Sequence[str],
    events: Sequence[_Event],
    window_seconds: float,
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    refs = [{"record_index": event.input_index} for event in events]
    identity = json.dumps(
        [pattern, list(key), [event.fingerprint for event in events]],
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    correlation_id = "corr-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    start = events[0].timestamp
    end = events[-1].timestamp
    return {
        "correlation_id": correlation_id,
        "event_ids": [event.event_id for event in events if event.event_id is not None],
        "record_references": refs,
        "source_ips": _unique_values(events, "source_ip"),
        "destination_ips": _unique_values(events, "destination_ip"),
        "source_ports": _unique_values(events, "source_port"),
        "destination_ports": _unique_values(events, "destination_port"),
        "protocols": _unique_values(events, "protocol"),
        "device_ids": _unique_values(events, "device_id"),
        "start_timestamp": start.isoformat().replace("+00:00", "Z"),
        "end_timestamp": end.isoformat().replace("+00:00", "Z"),
        "event_count": len(events),
        "evidence_level": "suspicious_pattern",
        "confirmed_attack": False,
        "pattern": pattern,
        "matched_rule": matched_rule,
        "evidence": {
            **_metrics(events, window_seconds),
            **dict(evidence),
        },
    }


class TemporalCorrelationService:
    """Correlate anomaly outputs with timestamped, optionally enriched flows.

    Records use canonical context keys: ``timestamp``, ``event_id``,
    ``source_ip``, ``destination_ip``, ``source_port``, ``destination_port``,
    ``device_id``, ``protocol``, ``direction``, ``is_anomaly``, and optionally
    ``anomaly_score``. The flow dataset's actual packet/byte column names are
    also understood. Ground-truth ``Label`` is never read.
    """

    def __init__(self, config: TemporalCorrelationConfig | None = None) -> None:
        self.config = config or TemporalCorrelationConfig()
        self.last_run: CorrelationReport | None = None

    def correlate(
        self,
        flow_records: Iterable[Mapping[str, Any]] | Any,
        detection_results: Sequence[Mapping[str, Any]] | None = None,
    ) -> CorrelationReport:
        """Return time-window findings plus rule-skipping and data-quality counts.

        When model results are provided separately, they must align one-to-one
        with flow records by position. Alternatively, each flow record can
        already contain the model's ``is_anomaly`` and ``anomaly_score`` keys.
        """
        records = _as_records(flow_records)
        if detection_results is not None and len(detection_results) != len(records):
            raise ValueError("detection_results must align one-to-one with flow_records.")

        stats: dict[str, Any] = {
            "records_received": len(records),
            "duplicate_records_dropped": 0,
            "invalid_or_missing_timestamps": 0,
            "records_without_anomaly_flag": 0,
            "non_anomalous_records": 0,
            "anomalous_records": 0,
            "timestamped_anomalies": 0,
        }
        skipped: dict[str, str] = {}
        events: list[_Event] = []
        seen_ids: set[str] = set()
        seen_fingerprints: set[str] = set()
        for index, original in enumerate(records):
            record = dict(original)
            if detection_results is not None:
                prediction = detection_results[index]
                if not isinstance(prediction, Mapping):
                    raise TypeError("Each detection result must be a mapping.")
                record_id = _identifier(record.get("event_id"))
                prediction_id = _identifier(prediction.get("event_id"))
                if (
                    record_id is not None
                    and prediction_id is not None
                    and record_id != prediction_id
                ):
                    raise ValueError(
                        f"Detection result event_id does not match flow record at index {index}."
                    )
                for key in ("event_id", "anomaly_score", "is_anomaly", "model_version"):
                    if key in prediction:
                        record[key] = prediction[key]

            event_id = record.get("event_id")
            identity = _identifier(event_id)
            fingerprint = _fingerprint(record)
            if (identity is not None and identity in seen_ids) or fingerprint in seen_fingerprints:
                stats["duplicate_records_dropped"] += 1
                continue
            if identity is not None:
                seen_ids.add(identity)
            seen_fingerprints.add(fingerprint)
            event = _event_from_record(record, index, fingerprint)
            if event.timestamp is None:
                stats["invalid_or_missing_timestamps"] += 1
            if "is_anomaly" not in record or not isinstance(record["is_anomaly"], bool):
                stats["records_without_anomaly_flag"] += 1
                continue
            if not event.is_anomaly:
                stats["non_anomalous_records"] += 1
                continue
            stats["anomalous_records"] += 1
            if event.timestamp is None:
                continue
            stats["timestamped_anomalies"] += 1
            events.append(event)

        findings: list[dict[str, Any]] = []
        timed = [event for event in events if event.timestamp is not None]
        if not timed:
            skipped["repeated_anomalies"] = (
                "No records with both a valid timestamp and is_anomaly=true."
            )
            skipped["dos_like"] = "No timestamped anomalous records."
            skipped["ddos_like"] = "No timestamped anomalous records."
            skipped["port_scan_like"] = "No timestamped anomalous records."
            skipped["possible_exfiltration"] = "No timestamped anomalous records."
            report = CorrelationReport(findings, stats, skipped)
            self.last_run = report
            return report

        recurrence_groups = _groups(timed, _recurrence_key)
        if not recurrence_groups:
            skipped["repeated_anomalies"] = (
                "No source_ip, device_id, or destination_ip identifier was available."
            )
        for key, window in _time_windows(
            recurrence_groups,
            self.config.time_window_seconds,
            self.config.min_repeated_anomalies,
        ):
            findings.append(
                _correlation(
                    "repeated_anomalies",
                    f"At least {self.config.min_repeated_anomalies} anomalous flows "
                    f"for {key[0]}={key[1]} within {self.config.time_window_seconds:g}s.",
                    key,
                    window,
                    self.config.time_window_seconds,
                    {"entity_type": key[0], "entity": key[1]},
                )
            )

        self._add_dos_findings(timed, findings, skipped)
        self._add_ddos_findings(timed, findings, skipped)
        self._add_portscan_findings(timed, findings, skipped)
        self._add_exfil_findings(timed, findings, skipped)
        findings.sort(
            key=lambda finding: (
                finding["start_timestamp"],
                finding["pattern"],
                finding["correlation_id"],
            )
        )
        report = CorrelationReport(findings, stats, skipped)
        self.last_run = report
        return report

    def _add_dos_findings(
        self,
        events: Sequence[_Event],
        findings: list[dict[str, Any]],
        skipped: dict[str, str],
    ) -> None:
        def key_for(event: _Event) -> tuple[str, ...] | None:
            endpoint = (
                ("destination_ip", event.destination_ip)
                if event.destination_ip is not None
                else ("source_ip", event.source_ip)
                if event.source_ip is not None
                else ("device_id", event.device_id)
                if event.device_id is not None
                else None
            )
            if endpoint is None:
                return None
            return (*endpoint, event.protocol or "")

        groups = _groups(events, key_for)
        if not groups:
            skipped["dos_like"] = "Requires a source, destination, or device identifier."
            return
        if (
            self.config.dos_min_total_bytes is None
            and self.config.dos_min_bytes_per_second is None
            and self.config.dos_min_packets_per_second is None
        ):
            skipped["dos_like"] = (
                "Disabled: configure dos_min_total_bytes and/or "
                "dos_min_bytes_per_second or dos_min_packets_per_second "
                "after validating field units."
            )
            return
        for key, window in _time_windows(
            groups, self.config.time_window_seconds, self.config.min_repeated_anomalies
        ):
            metrics = _metrics(window, self.config.time_window_seconds)
            bytes_match = (
                self.config.dos_min_total_bytes is not None
                and metrics["cumulative_bytes"] is not None
                and metrics["cumulative_bytes"] >= self.config.dos_min_total_bytes
            )
            rate_match = (
                self.config.dos_min_bytes_per_second is not None
                and metrics["peak_flow_bytes_per_second"] is not None
                and metrics["peak_flow_bytes_per_second"]
                >= self.config.dos_min_bytes_per_second
            )
            packet_rate_match = (
                self.config.dos_min_packets_per_second is not None
                and metrics["peak_flow_packets_per_second"] is not None
                and metrics["peak_flow_packets_per_second"]
                >= self.config.dos_min_packets_per_second
            )
            if bytes_match or rate_match or packet_rate_match:
                findings.append(
                    _correlation(
                        "dos_like",
                        "Repeated anomalous flows for one endpoint exceeded a configured "
                        "byte-volume, byte-rate, or packet-rate threshold.",
                        key,
                        window,
                        self.config.time_window_seconds,
                        {
                            "configured_total_bytes_threshold": self.config.dos_min_total_bytes,
                            "configured_peak_bytes_per_second_threshold": self.config.dos_min_bytes_per_second,
                            "configured_peak_packets_per_second_threshold": self.config.dos_min_packets_per_second,
                            "volume_threshold_matched": bytes_match,
                            "rate_threshold_matched": rate_match,
                            "packet_rate_threshold_matched": packet_rate_match,
                        },
                    )
                )
        if not any(item["pattern"] == "dos_like" for item in findings) and not skipped.get(
            "dos_like"
        ):
            skipped["dos_like"] = "No qualifying repeated volume/rate window met configured thresholds."

    def _add_ddos_findings(
        self,
        events: Sequence[_Event],
        findings: list[dict[str, Any]],
        skipped: dict[str, str],
    ) -> None:
        def key_for(event: _Event) -> tuple[str, ...] | None:
            if event.destination_ip is None:
                return None
            return ("destination_ip", event.destination_ip, event.protocol or "")

        groups = _groups(events, key_for)
        if not groups:
            skipped["ddos_like"] = "Requires destination_ip and timestamped anomalous flows."
            return
        if (
            self.config.ddos_min_total_bytes is None
            and self.config.ddos_min_bytes_per_second is None
            and self.config.ddos_min_packets_per_second is None
        ):
            skipped["ddos_like"] = (
                "Disabled: configure ddos_min_total_bytes and/or "
                "ddos_min_bytes_per_second or ddos_min_packets_per_second "
                "after validating field units."
            )
            return
        before = len(findings)
        for key, window in _time_windows(
            groups, self.config.time_window_seconds, self.config.min_repeated_anomalies
        ):
            sources = _unique_values(window, "source_ip")
            if len(sources) < self.config.ddos_min_distinct_sources:
                continue
            metrics = _metrics(window, self.config.time_window_seconds)
            bytes_match = (
                self.config.ddos_min_total_bytes is not None
                and metrics["cumulative_bytes"] is not None
                and metrics["cumulative_bytes"] >= self.config.ddos_min_total_bytes
            )
            rate_match = (
                self.config.ddos_min_bytes_per_second is not None
                and metrics["peak_flow_bytes_per_second"] is not None
                and metrics["peak_flow_bytes_per_second"]
                >= self.config.ddos_min_bytes_per_second
            )
            packet_rate_match = (
                self.config.ddos_min_packets_per_second is not None
                and metrics["peak_flow_packets_per_second"] is not None
                and metrics["peak_flow_packets_per_second"]
                >= self.config.ddos_min_packets_per_second
            )
            if not bytes_match and not rate_match and not packet_rate_match:
                continue
            findings.append(
                _correlation(
                    "ddos_like",
                    f"At least {self.config.ddos_min_distinct_sources} distinct sources "
                    f"had high-volume/rate anomalous flows to one destination within "
                    f"{self.config.time_window_seconds:g}s.",
                    key,
                    window,
                    self.config.time_window_seconds,
                    {
                        "distinct_source_count": len(sources),
                        "configured_min_distinct_sources": self.config.ddos_min_distinct_sources,
                        "configured_total_bytes_threshold": self.config.ddos_min_total_bytes,
                        "configured_peak_bytes_per_second_threshold": self.config.ddos_min_bytes_per_second,
                        "configured_peak_packets_per_second_threshold": self.config.ddos_min_packets_per_second,
                        "volume_threshold_matched": bytes_match,
                        "rate_threshold_matched": rate_match,
                        "packet_rate_threshold_matched": packet_rate_match,
                    },
                )
            )
        if len(findings) == before:
            skipped["ddos_like"] = (
                "No destination window met the configured anomaly, source-diversity, "
                "and volume/rate requirements."
            )

    def _add_portscan_findings(
        self,
        events: Sequence[_Event],
        findings: list[dict[str, Any]],
        skipped: dict[str, str],
    ) -> None:
        def key_for(event: _Event) -> tuple[str, ...] | None:
            entity = (
                ("source_ip", event.source_ip)
                if event.source_ip is not None
                else ("device_id", event.device_id)
                if event.device_id is not None
                else None
            )
            return (*entity, event.protocol or "") if entity is not None else None

        groups = _groups(events, key_for)
        if not groups:
            skipped["port_scan_like"] = "Requires source_ip or device_id."
            return
        before = len(findings)
        for key, window in _time_windows(
            groups, self.config.time_window_seconds, self.config.min_repeated_anomalies
        ):
            ports = _unique_values(window, "destination_port")
            hosts = _unique_values(window, "destination_ip")
            ports_match = len(ports) >= self.config.portscan_min_distinct_destination_ports
            hosts_match = len(hosts) >= self.config.portscan_min_distinct_destination_hosts
            if not ports_match and not hosts_match:
                continue
            findings.append(
                _correlation(
                    "port_scan_like",
                    "Repeated anomalous flows from one source covered the configured "
                    "number of distinct destination ports or hosts.",
                    key,
                    window,
                    self.config.time_window_seconds,
                    {
                        "distinct_destination_ports": ports,
                        "distinct_destination_hosts": hosts,
                        "port_threshold_matched": ports_match,
                        "host_threshold_matched": hosts_match,
                    },
                )
            )
        if len(findings) == before:
            skipped["port_scan_like"] = (
                "No source window met the configured destination-port or host diversity threshold."
            )

    def _add_exfil_findings(
        self,
        events: Sequence[_Event],
        findings: list[dict[str, Any]],
        skipped: dict[str, str],
    ) -> None:
        outbound = {value.casefold() for value in self.config.outbound_direction_values}
        outbound_events = [
            event
            for event in events
            if event.direction is not None and event.direction.casefold() in outbound
        ]
        if not outbound_events:
            skipped["possible_exfiltration"] = (
                "Requires a trusted direction field explicitly identifying outbound/egress flows."
            )
            return

        def key_for(event: _Event) -> tuple[str, ...] | None:
            entity = (
                ("source_ip", event.source_ip)
                if event.source_ip is not None
                else ("device_id", event.device_id)
                if event.device_id is not None
                else None
            )
            return (*entity, event.protocol or "") if entity is not None else None

        groups = _groups(outbound_events, key_for)
        if not groups:
            skipped["possible_exfiltration"] = (
                "Outbound direction is present, but source_ip or device_id is missing."
            )
            return
        if self.config.exfil_min_bytes is None:
            skipped["possible_exfiltration"] = (
                "Disabled: configure exfil_min_bytes only after validating transfer units "
                "and outbound direction context."
            )
            return
        before = len(findings)
        for key, window in _time_windows(
            groups, self.config.time_window_seconds, 1
        ):
            known_bytes = [event.byte_count for event in window if event.byte_count is not None]
            if not known_bytes:
                continue
            total_bytes = sum(known_bytes)
            if total_bytes < self.config.exfil_min_bytes:
                continue
            findings.append(
                _correlation(
                    "possible_exfiltration",
                    "Explicitly outbound flow bytes met the configured transfer-volume threshold.",
                    key,
                    window,
                    self.config.time_window_seconds,
                    {
                        "outbound_bytes": total_bytes,
                        "configured_min_bytes": self.config.exfil_min_bytes,
                        "direction_values": sorted(
                            {event.direction for event in window if event.direction is not None}
                        ),
                        "direction_source": "record direction field; deployment must verify its semantics",
                    },
                )
            )
        if len(findings) == before:
            skipped["possible_exfiltration"] = (
                "No eligible outbound window had byte fields meeting the configured threshold."
            )

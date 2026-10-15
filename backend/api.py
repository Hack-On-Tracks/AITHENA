"""Flask API for the existing LeakLens detection, correlation, and graph modules."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any

import pandas as pd
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException, UnsupportedMediaType

from backend.detection.anomaly_model import IsolationForestAnomalyModel
from backend.detection.feature_selection import (
    OPTIONAL_FEATURES,
    REQUIRED_FEATURES,
)
from backend.graph.correlation import CorrelationReport, TemporalCorrelationService
from backend.graph.graph_builder import build_knowledge_graph, graph_statistics, graph_to_dict


_DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parents[1]
    / "artifacts"
    / "detection"
    / "isolation_forest.joblib"
)
_CONTEXT_FIELDS = (
    "event_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "device_id",
    "protocol",
)
_FLOW_DETAIL_FIELDS = tuple(dict.fromkeys(
    (*_CONTEXT_FIELDS, *REQUIRED_FEATURES, *OPTIONAL_FEATURES)
))
_UNSET = object()


@dataclass
class _ApiState:
    model: IsolationForestAnomalyModel | None
    model_error: str | None
    correlation_service: TemporalCorrelationService | None
    latest_predictions: list[dict[str, Any]] = field(default_factory=list)
    latest_alerts: list[dict[str, Any]] = field(default_factory=list)
    latest_correlations: CorrelationReport | None = None
    latest_graph: Any = None
    has_analysis: bool = False
    lock: RLock = field(default_factory=RLock)


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if pd.notna(value) and abs(value) != float("inf") else None
    if isinstance(value, dict):
        return {
            str(key): _json_safe(item)
            for key, item in value.items()
            if str(key).casefold() != "label"
        }
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "item") and callable(value.item):
        try:
            return _json_safe(value.item())
        except (TypeError, ValueError, OverflowError):
            return str(value)
    if hasattr(value, "isoformat") and callable(value.isoformat):
        return value.isoformat()
    return str(value)


def _flow_details(record: dict[str, Any]) -> dict[str, Any]:
    return {
        name: _json_safe(record[name])
        for name in _FLOW_DETAIL_FIELDS
        if name in record and name.casefold() != "label"
    }


def _error_response(code: str, message: str, status: int):
    return jsonify({"error": {"code": code, "message": message}}), status


def _records_from_request() -> list[dict[str, Any]]:
    if not request.is_json:
        raise UnsupportedMediaType()
    payload = request.get_json()
    if isinstance(payload, list):
        records_value = payload
    elif isinstance(payload, dict) and "records" in payload:
        records_value = payload["records"]
    else:
        raise ValueError("Request JSON must be a record list or an object with a 'records' list.")

    if not isinstance(records_value, list):
        raise ValueError("'records' must be a list.")
    records: list[dict[str, Any]] = []
    for index, record in enumerate(records_value):
        if not isinstance(record, dict):
            raise ValueError(f"Record at index {index} must be a JSON object.")
        if not record:
            raise ValueError(f"Record at index {index} cannot be empty.")
        records.append(
            {
                key: value
                for key, value in record.items()
                if key.casefold() != "label"
            }
        )
    return records


def _make_alerts(
    records: list[dict[str, Any]],
    predictions: list[dict[str, Any]],
    threshold: float,
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for record, prediction in zip(records, predictions, strict=True):
        if not prediction["is_anomaly"]:
            continue
        score = prediction["anomaly_score"]
        alert = {
            "event_id": prediction["event_id"],
            "anomaly_score": score,
            "is_anomaly": True,
            "model_version": prediction["model_version"],
            "reason": (
                f"Isolation Forest anomaly score {score:g} exceeded configured "
                f"threshold {threshold:g}."
            ),
            "flow": _flow_details(record),
        }
        alerts.append(alert)
    return alerts


def create_app(
    *,
    model_path: str | Path | None = None,
    model: IsolationForestAnomalyModel | None | object = _UNSET,
    correlation_service: TemporalCorrelationService | None | object = _UNSET,
) -> Flask:
    """Create the API app, loading the fitted model once and never retraining."""
    app = Flask(__name__)
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    app.config["JSON_SORT_KEYS"] = False

    load_error: str | None = None
    if model is _UNSET:
        artifact_path = Path(model_path) if model_path is not None else _DEFAULT_MODEL_PATH
        try:
            loaded_model: IsolationForestAnomalyModel | None = (
                IsolationForestAnomalyModel.load(artifact_path)
            )
        except Exception:
            app.logger.exception("Unable to load the configured LeakLens model artifact.")
            loaded_model = None
            load_error = "model_artifact_unavailable"
    else:
        loaded_model = model if isinstance(model, IsolationForestAnomalyModel) else None
        if model is None:
            load_error = "model_artifact_unavailable"

    if correlation_service is _UNSET:
        active_correlation_service: TemporalCorrelationService | None = (
            TemporalCorrelationService()
        )
    else:
        active_correlation_service = (
            correlation_service
            if isinstance(correlation_service, TemporalCorrelationService)
            else None
        )

    state = _ApiState(
        model=loaded_model,
        model_error=load_error,
        correlation_service=active_correlation_service,
    )
    app.extensions["leaklens_api_state"] = state

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException):
        descriptions = {
            400: ("bad_request", "The request could not be parsed."),
            404: ("not_found", "The requested API route was not found."),
            405: ("method_not_allowed", "The HTTP method is not supported for this route."),
            415: ("unsupported_media_type", "Use application/json for this request."),
        }
        code, message = descriptions.get(
            error.code or 500,
            ("http_error", "The request could not be completed."),
        )
        return _error_response(code, message, error.code or 500)

    @app.get("/api/health")
    def health():
        model_available = state.model is not None
        correlation_available = state.correlation_service is not None
        graph_available = True
        components = {
            "model": {
                "available": model_available,
                "model_version": (
                    state.model.config.model_version if state.model is not None else None
                ),
            },
            "temporal_correlation": {"available": correlation_available},
            "knowledge_graph": {"available": graph_available},
        }
        available = all(
            component["available"] for component in components.values()
        )
        return jsonify(
            {
                "status": "ok" if available else "degraded",
                "components": components,
            }
        )

    @app.post("/api/analyze")
    def analyze():
        try:
            records = _records_from_request()
        except ValueError as error:
            return _error_response("invalid_request", str(error), 400)

        if not records:
            report = CorrelationReport(
                correlations=[],
                stats={"records_received": 0},
                skipped_rules={},
            )
            graph = build_knowledge_graph()
            with state.lock:
                state.latest_predictions = []
                state.latest_alerts = []
                state.latest_correlations = report
                state.latest_graph = graph
                state.has_analysis = True
            return jsonify(
                {
                    "predictions": [],
                    "alerts": [],
                    "correlations": [],
                    "graph_statistics": graph_statistics(graph),
                }
            )

        if state.model is None:
            return _error_response(
                "model_unavailable",
                "The anomaly detection model is unavailable.",
                503,
            )
        if state.correlation_service is None:
            return _error_response(
                "correlation_unavailable",
                "The temporal correlation component is unavailable.",
                503,
            )

        try:
            feature_frame = pd.DataFrame(records)
            predictions = state.model.predict(feature_frame)
            if len(predictions) != len(records):
                raise RuntimeError(
                    "The anomaly model returned an unexpected number of predictions."
                )
            predictions = [_json_safe(prediction) for prediction in predictions]
            enriched_records = [
                record | {
                    key: value
                    for key, value in prediction.items()
                    if key not in {"event_id"} or value is not None
                }
                for record, prediction in zip(records, predictions, strict=True)
            ]
            correlations = state.correlation_service.correlate(
                enriched_records,
                predictions,
            )
            graph = build_knowledge_graph(
                enriched_records,
                detection_results=predictions,
                correlation_results=correlations,
            )
            alerts = _make_alerts(
                enriched_records,
                predictions,
                state.model.config.score_threshold,
            )
        except (TypeError, ValueError) as error:
            return _error_response("invalid_records", str(error), 422)
        except Exception:
            app.logger.exception("LeakLens analysis request failed.")
            return _error_response(
                "analysis_failed",
                "The records could not be analyzed.",
                500,
            )

        with state.lock:
            state.latest_predictions = predictions
            state.latest_alerts = alerts
            state.latest_correlations = correlations
            state.latest_graph = graph
            state.has_analysis = True

        return jsonify(
            {
                "predictions": [
                    {
                        **prediction,
                        "flow": _flow_details(record),
                    }
                    for record, prediction in zip(
                        enriched_records, predictions, strict=True
                    )
                ],
                "alerts": alerts,
                "correlations": correlations.correlations,
                "graph_statistics": graph_statistics(graph),
            }
        )

    @app.get("/api/alerts")
    def alerts():
        with state.lock:
            return jsonify(
                {
                    "analysis_available": state.has_analysis,
                    "alerts": list(state.latest_alerts),
                }
            )

    @app.get("/api/correlations")
    def correlations():
        with state.lock:
            report = state.latest_correlations
            return jsonify(
                {
                    "analysis_available": state.has_analysis,
                    "correlations": report.correlations if report else [],
                    "stats": report.stats if report else {},
                    "skipped_rules": report.skipped_rules if report else {},
                }
            )

    @app.get("/api/graph")
    def graph():
        with state.lock:
            graph_value = state.latest_graph
            return jsonify(
                {
                    "analysis_available": state.has_analysis,
                    "statistics": (
                        graph_statistics(graph_value)
                        if graph_value is not None
                        else {"node_count": 0, "edge_count": 0, "node_type_counts": {}}
                    ),
                    "graph": (
                        graph_to_dict(graph_value)
                        if graph_value is not None
                        else graph_to_dict(build_knowledge_graph())
                    ),
                }
            )

    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    create_app().run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()

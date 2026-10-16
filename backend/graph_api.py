"""Thin Flask API exposing the EXISTING temporal-correlation and NetworkX
knowledge-graph modules for the live frontend — graph + correlation only.

This does NOT reimplement or modify any teammate module. It imports and calls
them directly:
  - backend.graph.correlation.TemporalCorrelationService  (temporal correlation)
  - backend.graph.graph_builder.build_knowledge_graph / graph_to_dict (NetworkX)

The Isolation Forest model is intentionally not loaded here (graph+correlation
only, per integration decision). Each incoming flow record must already carry an
`is_anomaly` boolean — in this integration that flag is produced by the existing
LeakLens JS device-risk engine (novelty / large-transfer), not fabricated here.
Run:  python -m backend.graph_api   (serves 127.0.0.1:5001)
"""
from __future__ import annotations

import logging
from typing import Any

from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException, UnsupportedMediaType

from backend.graph.correlation import TemporalCorrelationService
from backend.graph.graph_builder import (
    build_knowledge_graph,
    graph_statistics,
    graph_to_dict,
)

logger = logging.getLogger("leaklens.graph_api")


def _records_from_request() -> list[dict[str, Any]]:
    if not request.is_json:
        raise UnsupportedMediaType()
    payload = request.get_json()
    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict) and "records" in payload:
        records = payload["records"]
    else:
        raise ValueError("Request JSON must be a record list or an object with a 'records' list.")
    if not isinstance(records, list):
        raise ValueError("'records' must be a list.")
    for i, r in enumerate(records):
        if not isinstance(r, dict):
            raise ValueError(f"Record at index {i} must be a JSON object.")
    return records


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    service = TemporalCorrelationService()

    @app.errorhandler(HTTPException)
    def _http_err(err: HTTPException):
        return jsonify({"error": {"code": err.name, "message": err.description}}), err.code

    @app.get("/api/health")
    def health():
        return jsonify({
            "status": "ok",
            "components": {
                # ML scoring intentionally deferred in this integration.
                "model": {"available": False, "note": "Isolation Forest not loaded (graph+correlation only)"},
                "temporal_correlation": {"available": True},
                "knowledge_graph": {"available": True},
            },
        })

    @app.post("/api/graph-correlate")
    def graph_correlate():
        try:
            records = _records_from_request()
        except (ValueError, UnsupportedMediaType) as exc:
            return jsonify({"error": {"code": "bad_request", "message": str(exc)}}), 400

        # Reuse the teammate's temporal correlation unchanged. It only acts on
        # records already flagged is_anomaly=true and with valid timestamps.
        try:
            report = service.correlate(records)
            correlations = report.correlations
            stats = report.stats
            skipped = report.skipped_rules
        except ValueError:
            # e.g. "No records with both a valid timestamp and is_anomaly=true."
            correlations, stats, skipped = [], {"records_received": len(records)}, {}

        # Reuse the teammate's NetworkX builder unchanged.
        graph = build_knowledge_graph(records, None, correlations)
        return jsonify({
            "analysis_available": True,
            "statistics": graph_statistics(graph),
            "graph": graph_to_dict(graph),
            "correlations": correlations,
            "stats": stats,
            "skipped_rules": skipped,
        })

    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = create_app()
    app.run(host="127.0.0.1", port=5001, debug=False)


if __name__ == "__main__":
    main()

# LeakLens Flask API

## Run

Install declared dependencies if needed, then start the API from the repository
root in PowerShell:

```powershell
.\.venv\Scripts\python.exe -m backend.api
```

The development server binds to `127.0.0.1:5000` with Flask debug mode disabled.
The app loads the fitted model once from
`artifacts/detection/isolation_forest.joblib` during startup; it does not train
or replace the model. If the artifact cannot be loaded, health reports a
degraded model component and analysis returns HTTP 503.

The API enables Flask-CORS for `/api/*`. The existing frontend is a static
prototype whose JavaScript uses generated sample data and does not currently
call an API; no frontend files or expectations were changed.

## Endpoints

### `GET /api/health`

Returns component availability, without exposing local filesystem paths:

```json
{
  "status": "ok",
  "components": {
    "model": {"available": true, "model_version": "isolation-forest-v1"},
    "temporal_correlation": {"available": true},
    "knowledge_graph": {"available": true}
  }
}
```

### `POST /api/analyze`

Accepts either a record list or an object containing a `records` list. Every
record must be a JSON object with all features fitted into the current model.
The current artifact requires the 15 feature-selection `REQUIRED_FEATURES`
and seven optional features that were present when it was trained (22 input
features total). Ground-truth `Label` is stripped before scoring and never
returned.

```json
{
  "records": [
    {
      "Flow Duration": 10,
      "Total Fwd Packets": 2,
      "Total Backward Packets": 1
    }
  ]
}
```

The abbreviated record above is illustrative only and will not pass validation
for the current 22-feature artifact. Successful response contains:

- `predictions`: one entry per input record, with the actual `event_id` when
  supplied, `anomaly_score`, `is_anomaly`, `model_version`, and filtered
  `flow` details.
- `alerts`: entries only for predictions where the existing model's
  `is_anomaly` is true.
- `correlations`: actual findings from `TemporalCorrelationService`.
- `graph_statistics`: node, edge, and node-type counts for the graph built from
  that input and those findings.

Actual anomaly scores are `-IsolationForest.decision_function`; higher scores
mean more anomalous, not a probability. An alert's reason states the observed
score and configured threshold; it does not assert an attack type.

An empty `records` list returns an empty analysis result, replaces the latest
in-memory analysis state, and creates no alerts or graph nodes. Missing
`records`, malformed JSON, non-object entries, and malformed feature inputs
return JSON errors. Missing model/correlation components return HTTP 503.

### `GET /api/alerts`

Returns the alerts generated from the most recently completed `/api/analyze`
call, plus `analysis_available`. Before any analysis, the list is empty and
`analysis_available` is false. Alert flow details include only known feature
and context fields actually present in the request.

### `GET /api/correlations`

Returns the latest `TemporalCorrelationService` report as `correlations`,
`stats`, and `skipped_rules`. Before analysis, these are empty objects/lists.
The current raw Parquet dataset has no timestamps or endpoint identifiers, so
temporal groups cannot be formed from un-enriched raw records.

### `GET /api/graph`

Returns `analysis_available`, `statistics`, and the graph builder's
JSON-serializable node-link output under `graph`. Only supplied identifiers and
the actual correlation report are represented. Missing IPs, timestamps,
devices, and event IDs are not synthesized.

Analysis results are held in process memory and represent the latest completed
request. This API is a local development integration, not persistent storage
or an authenticated production service.

## Error response

Client and server errors use:

```json
{"error": {"code": "invalid_records", "message": "..." }}
```

Unexpected server exceptions are logged server-side and return a generic
message without a traceback or filesystem path.

## Tests

Run the API tests and existing model/correlation tests:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_api tests.test_temporal_correlation tests.test_anomaly_model
```

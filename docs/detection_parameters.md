# LeakLens detection parameters

## Dataset inspected

The archive `C:\Users\KEONA\Downloads\archive.zip` was readable and contained eight Parquet files. They were extracted to the project's `data/raw/` directory without replacing existing files. Inspection used pandas and pyarrow, scanning every row in batches.

| File | Rows | Label values and row counts |
|---|---:|---|
| `Benign-Monday-no-metadata.parquet` | 458,831 | `Benign`: 458,831 |
| `Botnet-Friday-no-metadata.parquet` | 176,038 | `Benign`: 174,601; `Bot`: 1,437 |
| `Bruteforce-Tuesday-no-metadata.parquet` | 389,714 | `Benign`: 380,564; `FTP-Patator`: 5,931; `SSH-Patator`: 3,219 |
| `DDoS-Friday-no-metadata.parquet` | 221,264 | `DDoS`: 128,014; `Benign`: 93,250 |
| `DoS-Wednesday-no-metadata.parquet` | 584,991 | `Benign`: 391,235; `DoS slowloris`: 5,385; `DoS Slowhttptest`: 5,228; `DoS GoldenEye`: 10,286; `DoS Hulk`: 172,846; `Heartbleed`: 11 |
| `Infiltration-Thursday-no-metadata.parquet` | 207,630 | `Benign`: 207,594; `Infiltration`: 36 |
| `Portscan-Friday-no-metadata.parquet` | 119,522 | `Benign`: 117,566; `PortScan`: 1,956 |
| `WebAttacks-Thursday-no-metadata.parquet` | 155,820 | `Benign`: 153,677; `Web Attack \uFFFD Brute Force`: 1,470; `Web Attack \uFFFD Sql Injection`: 21; `Web Attack \uFFFD XSS`: 652 |
| **Total** | **2,313,810** | **1,977,318 benign; 336,492 non-benign** |

The `\uFFFD` sequence above represents the actual U+FFFD replacement character stored in each of the three web-attack label values; it is not a dash. Preserve the raw label values for evaluation and investigate their source encoding before normalizing them.

## Confirmed schema

All eight files have the same 78 column names: 77 numeric-valued feature columns and a dictionary-encoded string `Label`. The table gives the physical Arrow type in `Benign-Monday-no-metadata.parquet`; integer widths differ in several other files, as listed after the table. No columns for timestamps, source/destination addresses, or ports are present.

| Column | Arrow type |
|---|---|
| `Protocol` | `int8` |
| `Flow Duration` | `int32` |
| `Total Fwd Packets` | `int32` |
| `Total Backward Packets` | `int32` |
| `Fwd Packets Length Total` | `int32` |
| `Bwd Packets Length Total` | `int32` |
| `Fwd Packet Length Max` | `int16` |
| `Fwd Packet Length Min` | `int16` |
| `Fwd Packet Length Mean` | `float` |
| `Fwd Packet Length Std` | `float` |
| `Bwd Packet Length Max` | `int16` |
| `Bwd Packet Length Min` | `int16` |
| `Bwd Packet Length Mean` | `float` |
| `Bwd Packet Length Std` | `float` |
| `Flow Bytes/s` | `double` |
| `Flow Packets/s` | `double` |
| `Flow IAT Mean` | `float` |
| `Flow IAT Std` | `float` |
| `Flow IAT Max` | `int32` |
| `Flow IAT Min` | `int32` |
| `Fwd IAT Total` | `int32` |
| `Fwd IAT Mean` | `float` |
| `Fwd IAT Std` | `float` |
| `Fwd IAT Max` | `int32` |
| `Fwd IAT Min` | `int32` |
| `Bwd IAT Total` | `int32` |
| `Bwd IAT Mean` | `float` |
| `Bwd IAT Std` | `float` |
| `Bwd IAT Max` | `int32` |
| `Bwd IAT Min` | `int32` |
| `Fwd PSH Flags` | `int8` |
| `Bwd PSH Flags` | `int8` |
| `Fwd URG Flags` | `int8` |
| `Bwd URG Flags` | `int8` |
| `Fwd Header Length` | `int32` |
| `Bwd Header Length` | `int32` |
| `Fwd Packets/s` | `float` |
| `Bwd Packets/s` | `float` |
| `Packet Length Min` | `int16` |
| `Packet Length Max` | `int16` |
| `Packet Length Mean` | `float` |
| `Packet Length Std` | `float` |
| `Packet Length Variance` | `float` |
| `FIN Flag Count` | `int8` |
| `SYN Flag Count` | `int8` |
| `RST Flag Count` | `int8` |
| `PSH Flag Count` | `int8` |
| `ACK Flag Count` | `int8` |
| `URG Flag Count` | `int8` |
| `CWE Flag Count` | `int8` |
| `ECE Flag Count` | `int8` |
| `Down/Up Ratio` | `int8` |
| `Avg Packet Size` | `float` |
| `Avg Fwd Segment Size` | `float` |
| `Avg Bwd Segment Size` | `float` |
| `Fwd Avg Bytes/Bulk` | `int8` |
| `Fwd Avg Packets/Bulk` | `int8` |
| `Fwd Avg Bulk Rate` | `int8` |
| `Bwd Avg Bytes/Bulk` | `int8` |
| `Bwd Avg Packets/Bulk` | `int8` |
| `Bwd Avg Bulk Rate` | `int8` |
| `Subflow Fwd Packets` | `int32` |
| `Subflow Fwd Bytes` | `int32` |
| `Subflow Bwd Packets` | `int32` |
| `Subflow Bwd Bytes` | `int32` |
| `Init Fwd Win Bytes` | `int32` |
| `Init Bwd Win Bytes` | `int32` |
| `Fwd Act Data Packets` | `int32` |
| `Fwd Seg Size Min` | `int32` |
| `Active Mean` | `float` |
| `Active Std` | `float` |
| `Active Max` | `int32` |
| `Active Min` | `int32` |
| `Idle Mean` | `float` |
| `Idle Std` | `float` |
| `Idle Max` | `int32` |
| `Idle Min` | `int32` |
| `Label` | `dictionary<string, int8>` |

Schema differences are physical integer-width changes only; no files have missing or additional columns:

- `Botnet-Friday-no-metadata.parquet`, `DoS-Wednesday-no-metadata.parquet`, and `WebAttacks-Thursday-no-metadata.parquet`: `Fwd Seg Size Min` is `int8`.
- `Bruteforce-Tuesday-no-metadata.parquet`: `Fwd Act Data Packets` is `int16`; `Fwd Header Length` is `int64`.
- `DDoS-Friday-no-metadata.parquet`: `Total Fwd Packets`, `Total Backward Packets`, `Subflow Fwd Packets`, `Subflow Bwd Packets`, and `Fwd Act Data Packets` are `int16`; `Fwd Seg Size Min` is `int8`.
- `Infiltration-Thursday-no-metadata.parquet`: `Down/Up Ratio` is `int16`; `Total Fwd Packets`, `Subflow Fwd Packets`, and `Fwd Act Data Packets` are `int16`; `Fwd Seg Size Min` is `int8`.
- `Portscan-Friday-no-metadata.parquet`: `Total Fwd Packets`, `Total Backward Packets`, `Subflow Fwd Packets`, `Subflow Bwd Packets`, and `Fwd Act Data Packets` are `int16`; `Fwd Seg Size Min` is `int8`.

Before combining files, normalize these differing physical widths to a consistent numeric schema. `Label` is an outcome column, not an input feature. `Protocol` is stored as an integer but should be considered a protocol category, not presumed to be a continuous measurement.

## Data quality and available detection parameters

The full-row scan found no null/missing values and no positive or negative infinities in any column in these eight files. This observation applies to the extracted snapshot only; incoming live records still need validation for nulls, non-finite values, invalid ranges, and zero denominators.

Confirmed available directly:

- **Flow timing and duration:** `Flow Duration`; flow, forward, and backward inter-arrival-time (IAT) total/mean/std/min/max fields; `Active` and `Idle` mean/std/min/max.
- **Packets and bytes:** forward/backward packet totals; forward/backward packet-length totals; subflow packet and byte counts; packet length min/max/mean/std/variance; directional packet length statistics.
- **Rates:** `Flow Bytes/s`, `Flow Packets/s`, `Fwd Packets/s`, and `Bwd Packets/s`.
- **TCP flag aggregates:** per-flow FIN, SYN, RST, PSH, ACK, URG, CWE, and ECE counts, plus forward/backward PSH and URG counts. These are aggregate counters, not packet-level flag sequences.
- **Other flow features:** numeric `Protocol`, directional header lengths, `Down/Up Ratio`, average segment sizes, bulk statistics, initial forward/backward window bytes, and forward active data packet count.
- **Ground-truth labels:** the `Label` values listed above; use them only for offline evaluation, never as a runtime feature or rule input.

### Derived parameters

These can be computed per flow from the confirmed columns; they define feature candidates, not thresholds:

| Derived parameter | Formula | Guard |
|---|---|---|
| `Total Packets` | `Total Fwd Packets + Total Backward Packets` | Both source counts must be valid. |
| `Total Bytes` | `Fwd Packets Length Total + Bwd Packets Length Total` | Both source totals must be valid. |
| `Fwd Packet Share` | `Total Fwd Packets / Total Packets` | Define only when `Total Packets > 0`. |
| `Bwd Packet Share` | `Total Backward Packets / Total Packets` | Define only when `Total Packets > 0`. |
| `Fwd Byte Share` | `Fwd Packets Length Total / Total Bytes` | Define only when `Total Bytes > 0`. |
| `Bytes per Packet` | `Total Bytes / Total Packets` | Define only when `Total Packets > 0`. |
| `Flag Count per Packet` (optional, per flag) | `<flag> Flag Count / Total Packets` | Define only when `Total Packets > 0`; retain the raw flag count too. |

Use the provided rate fields directly until the units and conventions of `Flow Duration` are confirmed. The Parquet schema does not declare units, so do not derive rates from duration or compare duration/IAT values to time thresholds until the source-data unit and feature-generation conventions are verified. `Down/Up Ratio`, average packet size, and the listed rates already exist; avoid duplicating them under a second name without a specific reason.

## Parameters for a future Isolation Forest

The dataset offers 77 numeric-valued columns other than `Label`; these are the candidate input pool, not a requirement to use all of them. A future model configuration must explicitly select and version:

1. The feature columns and their canonical types, excluding `Label`; decide how to encode or otherwise handle categorical `Protocol`.
2. A training population (for anomaly detection, benign-only training is an option to evaluate), and a leakage-safe train/validation/test split. Keep labels outside the model inputs.
3. The Isolation Forest settings: `n_estimators`, `max_samples`, `max_features`, `contamination`, `bootstrap`, and `random_state`.
4. A score-to-alert decision policy calibrated on validation data, plus how the policy handles zero-denominator or invalid live features.

At the time of the initial dataset inspection, no model, parameter values, alert threshold, or accuracy claim had been established. The day-specific files have highly uneven class counts, so a random row split alone may overstate generalization across collection days.

## Parameters for attack-specific rules

Rules can only use observable flow evidence. No thresholds are set here.

| Candidate classification | Available evidence to evaluate | Important missing evidence / limitation |
|---|---|---|
| DoS / DDoS | Flow and directional packet/byte rates, total packet/byte volume, packet-size statistics, duration, and aggregate TCP flag counts. | A single flow lacks source/target identity and time-window aggregation; rate/volume evidence alone cannot reliably distinguish attack from legitimate high-volume activity. |
| Port scan | Per-flow packet counts, duration, protocol, and TCP flag counts may contribute as supporting evidence. | No source/destination address, destination port, or event timestamp: cannot count unique ports/targets per source or characterize scan cadence. Do not classify as a port scan from this table alone. |
| FTP/SSH brute force | Flow counts/rates and TCP flag statistics may be weak supporting evidence. | No endpoint identity, destination port/service, timestamps, authentication events, or payload: repeated failed logins cannot be established. |
| Web attacks (brute force, SQL injection, XSS) | Generic flow volume/rate fields are available only as context. | No HTTP method, URI, headers, request body, response, or payload; these attack types cannot be identified from these columns alone. |
| Bot | Flow rates, duration, IAT, and active/idle statistics can provide generic anomaly evidence. | No endpoint identity, DNS, payload, or temporal sequence across flows to establish command-and-control or bot behavior. |
| Infiltration | Generic flow statistics and timing can indicate anomalous activity. | No identities, host/process context, payload, or timestamped flow sequence to establish lateral movement or data exfiltration. |
| Heartbleed | Flow size/rate and protocol fields can be retained as context. | No TLS handshake/message or payload evidence to identify the vulnerability exploit. |

An Isolation Forest anomaly should therefore produce an **anomalous flow** result, not a specific attack name by itself. A specific attack classification should require explicit rule evidence that the available fields can support; otherwise return a generic anomaly/unknown classification and preserve the evidence and missing-context reason. The dataset's `Label` values are useful as offline ground truth but must not be presented as evidence available to a live detector.

## Missing metadata and recommended next step

- There is no event timestamp, source/destination address or identifier, source/destination port, or packet-level data.
- Flow duration and IAT units are not declared in the inspected Parquet metadata.
- TCP flags are flow-level counts, not packet sequences; payload, application-layer, authentication, host, and process evidence is absent.
- The labels are imbalanced and day-specific; web-attack strings contain U+FFFD, so label normalization must be deliberate and traceable.

The current Isolation Forest baseline and its held-out evaluation are documented below. Further work should validate a versioned feature set against the intended live input and assess the baseline on additional capture days. Resolve feature units and label encoding before adding duration-derived features; do not treat this baseline as attack classification or infer that its threshold is optimal.

## First-stage feature selection and preprocessing

`backend/detection/feature_selection.py` selects the following exact ordered feature list from a dataframe-like object or mapping:

1. `Flow Duration`
2. `Total Fwd Packets`
3. `Total Backward Packets`
4. `Fwd Packets Length Total`
5. `Bwd Packets Length Total`
6. `Flow Bytes/s`
7. `Flow Packets/s`
8. `Flow IAT Mean`
9. `Flow IAT Std`
10. `Fwd IAT Mean`
11. `Bwd IAT Mean`
12. `SYN Flag Count`
13. `RST Flag Count`
14. `FIN Flag Count`
15. `ACK Flag Count`
16. `Packet Length Mean`
17. `Packet Length Std`
18. `Fwd Packet Length Max`
19. `Bwd Packet Length Max`
20. `Active Mean`
21. `Idle Mean`
22. `Protocol`

The first 15 are required and were confirmed in all eight extracted Parquet schemas. The final seven are optional candidates, also confirmed in those schemas; if one is absent from a future input, it is excluded and reported by the selector. Missing required columns raise an explicit error. `Label` is returned separately for evaluation and never appears in the selected feature mapping.

The selected flow duration and IAT fields describe elapsed-time behavior, while packet/byte counts and rates describe volume and throughput. The four TCP flag counts offer aggregate connection-setup/teardown or reset evidence. Packet-length statistics capture flow shape; `Protocol` is retained as an optional numeric source field but represents a category, not a continuous quantity. None of these per-flow fields alone identifies an attack.

`backend/detection/preprocessing.py` fits on training features only. It converts non-finite values (`NaN`, positive/negative infinity) and `None` to missing, imputes observed missing values with each training column's median, removes all-missing and training-constant columns, then removes exact duplicate columns while retaining the first. It reports removed columns and the retained feature order. Later validation/test/inference calls must use `transform()` on that same fitted instance; it uses stored training medians and fails explicitly if a fitted input column is missing. The output is rows of numeric dictionaries. Labels are not accepted as a separate preprocessing argument or used for any fitted statistic.

This module does not calculate rates from duration, since units for `Flow Duration` and IAT fields are not established. It performs no division, so it introduces no zero-denominator case. Exact duplicate removal is deliberately conservative: overlapping meanings and strongly correlated features may remain. No scaling or classification behavior is implemented in this stage.

Candidate features excluded from the exact list include forward/backward packet-count rates, backward packet-length means/stds, packet length min/max/variance, forward/backward IAT totals/stds/min/max, forward/backward PSH/URG counts, other TCP flag counters, header lengths, down/up ratio, segment sizes, bulk fields, subflow counts/bytes, initial window sizes, forward active-data count, and Active/Idle std/min/max. They are excluded from this initial selection, not because the schema lacks them, but to keep the first feature set explicit and bounded. Timestamp, source/destination IPs, and ports are unavailable in the inspected dataset, so this stage cannot add time-windowed or per-host/per-port aggregations.

## Implemented Isolation Forest baseline

`backend/detection/anomaly_model.py` trains `sklearn.ensemble.IsolationForest` using only records whose separate `Label` value exactly matches `Benign`. Feature selection excludes `Label`; labels are only used to filter benign training rows and later to calculate offline evaluation metrics. The reusable model bundle includes the fitted estimator, fitted median preprocessing, feature order, model version, and settings. `predict()` does not retrain and returns `event_id` (or `null` when absent), `anomaly_score`, `is_anomaly`, and `model_version`.

The score convention is `anomaly_score = -IsolationForest.decision_function(X)`, so higher scores mean more anomalous. The decision is `anomaly_score > score_threshold`; the configurable baseline threshold is `0.0`, not an optimized or calibrated value. A score is not a probability. The Isolation Forest's `contamination="auto"` setting is also recorded separately from this score threshold.

The reproducible baseline settings are `n_estimators=200`, `max_samples="auto"`, `max_features=1.0`, `contamination="auto"`, `bootstrap=false`, `random_state=42`, `n_jobs=-1`, and `max_training_samples=100000`. Training records are sampled deterministically with seed 42 when the benign training file has more rows than the configured cap. Preprocessing is fitted only on that benign sample and reused unchanged for evaluation and inference. The fitted model currently retained all 22 features: no columns were all-missing, constant, or exact duplicates in the actual training sample.

### Measured dataset evaluation

The actual baseline was trained on the 100,000-record deterministic benign-only sample from `Benign-Monday-no-metadata.parquet`. That file contains 458,831 rows, all labelled `Benign`. Evaluation held out the other seven Parquet files by file (not by random row split), processing their 1,854,979 rows in batches. This is a file/day-separated evaluation, not evidence of generalization to other networks or future live traffic.

Ground-truth labels were collapsed only for offline binary scoring: `Benign` versus any non-`Benign` label. The label was not supplied to `predict()` or the feature matrix.

| Metric | Measured result |
|---|---:|
| Precision | 0.6214 |
| Recall | 0.7421 |
| F1 | 0.6764 |
| False positives (benign predicted anomalous) | 152,149 |
| False negatives (labelled attacks predicted benign) | 86,789 |

Confusion matrix, rows actual and columns predicted, in order `Benign`, `Attack`:

|  | Predicted Benign | Predicted Attack |
|---|---:|---:|
| Actual Benign | 1,366,338 | 152,149 |
| Actual Attack | 86,789 | 249,703 |

These are measured results at the stated default threshold, not optimal performance or multiclass attack identification. Isolation Forest is unsupervised, while the labels are dataset annotations; benign behavior and attack prevalence can differ across collection days. Training only on Monday and evaluating on other days also means day/domain shift can contribute to errors. A single flow-level anomaly score cannot identify attack type or establish DoS, scanning, or exfiltration. The dataset contains no event identifier, so predictions on these files have `event_id: null`.

The fitted local artifact is saved as `artifacts/detection/isolation_forest.joblib` and ignored by Git as a generated binary. Loading joblib artifacts can execute code; only load trusted artifacts produced by LeakLens. Reproduce the run by calling `train_and_evaluate_parquet()` in `backend/detection/detection_service.py` with the Monday file as `training_file`, the other seven Parquet files as `evaluation_files`, and the artifact path. Existing artifacts are not overwritten unless explicitly requested.

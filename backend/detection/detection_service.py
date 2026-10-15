"""Dataset-level training and held-out evaluation for LeakLens anomaly scoring."""

from __future__ import annotations

import random
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from .anomaly_model import IsolationForestAnomalyModel, IsolationForestConfig
from .feature_selection import LABEL_COLUMN, OPTIONAL_FEATURES, REQUIRED_FEATURES


def _selected_dataset_columns() -> list[str]:
    return [*REQUIRED_FEATURES, *OPTIONAL_FEATURES, LABEL_COLUMN]


def _sample_training_file(
    path: Path, config: IsolationForestConfig, benign_label: str
) -> tuple[dict[str, list[Any]], int, int]:
    if not path.is_file():
        raise FileNotFoundError(f"Training Parquet file not found: {path}")
    parquet = pq.ParquetFile(path)
    if LABEL_COLUMN not in parquet.schema_arrow.names:
        raise ValueError(f"Training file has no {LABEL_COLUMN!r} column: {path}")

    all_labels_table = pq.read_table(path, columns=[LABEL_COLUMN])
    all_labels = all_labels_table.column(LABEL_COLUMN).to_pylist()
    benign_indices = [
        index for index, label in enumerate(all_labels) if label == benign_label
    ]
    if not benign_indices:
        raise ValueError(f"No records have the verified benign label {benign_label!r}: {path}")
    benign_record_count = len(benign_indices)
    sample_limit = config.max_training_samples
    if sample_limit is not None and len(benign_indices) > sample_limit:
        benign_indices = sorted(
            random.Random(config.random_state).sample(benign_indices, sample_limit)
        )

    available = set(parquet.schema_arrow.names)
    missing_required = [name for name in REQUIRED_FEATURES if name not in available]
    if missing_required:
        raise ValueError(
            f"Training file is missing required features: {', '.join(missing_required)}"
        )
    columns = [name for name in _selected_dataset_columns() if name in available]
    table = pq.read_table(path, columns=columns)
    sampled = table.take(pa.array(benign_indices, type=pa.int64())).to_pandas()
    selected_features = {
        name: sampled[name].tolist()
        for name in [*REQUIRED_FEATURES, *OPTIONAL_FEATURES]
        if name in sampled.columns
    }
    labels = sampled[LABEL_COLUMN].tolist()
    return (
        selected_features | {LABEL_COLUMN: labels},
        len(all_labels),
        benign_record_count,
    )


def _evaluate_parquet(
    model: IsolationForestAnomalyModel,
    evaluation_paths: Sequence[Path],
    *,
    batch_size: int,
    benign_label: str,
) -> dict[str, Any]:
    true_positive = false_positive = true_negative = false_negative = 0
    file_results: list[dict[str, Any]] = []
    for path in evaluation_paths:
        if not path.is_file():
            raise FileNotFoundError(f"Evaluation Parquet file not found: {path}")
        parquet = pq.ParquetFile(path)
        available = set(parquet.schema_arrow.names)
        missing_required = [name for name in REQUIRED_FEATURES if name not in available]
        if missing_required:
            raise ValueError(
                f"Evaluation file {path.name} is missing required features: "
                + ", ".join(missing_required)
            )
        if LABEL_COLUMN not in available:
            raise ValueError(f"Evaluation file has no {LABEL_COLUMN!r} column: {path}")
        columns = [name for name in _selected_dataset_columns() if name in available]
        file_count = 0
        for batch in parquet.iter_batches(columns=columns, batch_size=batch_size):
            frame = batch.to_pandas()
            labels = frame[LABEL_COLUMN].tolist()
            records = model.predict(frame)
            for label, record in zip(labels, records, strict=True):
                actual_attack = label != benign_label
                predicted_attack = record["is_anomaly"]
                if actual_attack and predicted_attack:
                    true_positive += 1
                elif actual_attack:
                    false_negative += 1
                elif predicted_attack:
                    false_positive += 1
                else:
                    true_negative += 1
            file_count += len(labels)
        file_results.append({"file": path.name, "records": file_count})

    total = true_positive + false_positive + true_negative + false_negative
    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive
        else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if true_positive + false_negative
        else 0.0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    return {
        "evaluation_records": total,
        "confusion_matrix": {
            "labels": ["Benign", "Attack"],
            "rows_actual_columns_predicted": [
                [true_negative, false_positive],
                [false_negative, true_positive],
            ],
        },
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positives": false_positive,
        "false_negatives": false_negative,
        "files": file_results,
    }


def train_and_evaluate_parquet(
    training_file: str | Path,
    evaluation_files: Sequence[str | Path],
    artifact_path: str | Path,
    *,
    config: IsolationForestConfig | None = None,
    benign_label: str = "Benign",
    overwrite_artifact: bool = False,
) -> dict[str, Any]:
    """Train on benign rows in one file and evaluate only on separate files.

    Rows from the training file are excluded entirely from evaluation. The
    training file is sampled deterministically up to ``max_training_samples``.
    Evaluation reads in bounded Parquet batches and accumulates confusion
    counts rather than retaining predictions for the entire dataset.
    """
    model_config = config or IsolationForestConfig()
    training_path = Path(training_file).resolve()
    evaluation_paths = [Path(path).resolve() for path in evaluation_files]
    if not evaluation_paths:
        raise ValueError("At least one held-out evaluation Parquet file is required.")
    if training_path in evaluation_paths:
        raise ValueError("Training file must not also appear in evaluation files.")
    if len(set(evaluation_paths)) != len(evaluation_paths):
        raise ValueError("Evaluation files must not contain duplicates.")

    training_data, training_records_seen, benign_records = _sample_training_file(
        training_path, model_config, benign_label
    )
    model = IsolationForestAnomalyModel(model_config).fit(
        training_data, benign_label=benign_label
    )
    artifact = model.save(artifact_path, overwrite=overwrite_artifact)
    evaluation = _evaluate_parquet(
        model,
        evaluation_paths,
        batch_size=8192,
        benign_label=benign_label,
    )
    return {
        "model": model.metadata(),
        "training_file": str(training_path),
        "training_file_records": training_records_seen,
        "training_benign_records": benign_records,
        "training_records_used": model.training_records_used_,
        "artifact_path": str(artifact),
        "score_convention": "anomaly_score = -IsolationForest.decision_function; higher is more anomalous",
        "score_threshold": model.config.score_threshold,
        "evaluation": evaluation,
    }


def evaluate_records(
    model: IsolationForestAnomalyModel,
    records: Mapping[str, Sequence[Any]] | Any,
    labels: Sequence[Any],
    *,
    benign_label: str = "Benign",
) -> dict[str, Any]:
    """Evaluate labelled records in memory without passing labels to inference."""
    predictions = model.predict(records)
    if len(labels) != len(predictions):
        raise ValueError("Label count does not match the number of evaluated records.")
    tp = fp = tn = fn = 0
    for label, prediction in zip(labels, predictions, strict=True):
        actual_attack = label != benign_label
        predicted_attack = prediction["is_anomaly"]
        if actual_attack and predicted_attack:
            tp += 1
        elif actual_attack:
            fn += 1
        elif predicted_attack:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "evaluation_records": len(predictions),
        "confusion_matrix": {
            "labels": ["Benign", "Attack"],
            "rows_actual_columns_predicted": [[tn, fp], [fn, tp]],
        },
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positives": fp,
        "false_negatives": fn,
    }

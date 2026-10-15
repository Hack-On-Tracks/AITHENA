"""Isolation Forest baseline trained on explicitly labelled benign flows."""

from __future__ import annotations

import os
import random
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .feature_selection import LABEL_COLUMN, select_features
from .preprocessing import FittedFeaturePreprocessor


MODEL_VERSION = "isolation-forest-v1"


@dataclass(frozen=True)
class IsolationForestConfig:
    """Reproducible Isolation Forest and score threshold settings."""

    n_estimators: int = 200
    max_samples: int | float | str = "auto"
    max_features: int | float = 1.0
    contamination: float | str = "auto"
    bootstrap: bool = False
    random_state: int = 42
    n_jobs: int | None = -1
    score_threshold: float = 0.0
    max_training_samples: int | None = 100_000
    model_version: str = MODEL_VERSION


class IsolationForestAnomalyModel:
    """Train once, persist, and reuse an Isolation Forest for flow scoring.

    The public score convention is ``anomaly_score = -decision_function``:
    higher scores indicate more anomalous observations. A flow is anomalous
    exactly when its score is greater than the configured threshold.
    """

    def __init__(self, config: IsolationForestConfig | None = None) -> None:
        self.config = config or IsolationForestConfig()
        self._validate_config()
        self.preprocessor: FittedFeaturePreprocessor | None = None
        self.estimator: IsolationForest | None = None
        self.feature_names_in_: tuple[str, ...] = ()
        self.training_records_seen_: int = 0
        self.training_records_used_: int = 0
        self.benign_label_: str = "Benign"

    def _validate_config(self) -> None:
        if self.config.n_estimators < 1:
            raise ValueError("n_estimators must be at least 1.")
        if self.config.max_training_samples is not None and self.config.max_training_samples < 1:
            raise ValueError("max_training_samples must be positive or None.")
        if not np.isfinite(self.config.score_threshold):
            raise ValueError("score_threshold must be finite.")
        if not self.config.model_version:
            raise ValueError("model_version cannot be empty.")

    @property
    def is_fitted(self) -> bool:
        return self.estimator is not None and self.preprocessor is not None

    @staticmethod
    def _rows_to_matrix(rows: list[dict[str, float]], names: tuple[str, ...]) -> np.ndarray:
        if not names:
            raise ValueError("No usable features remain after preprocessing.")
        if not rows:
            return np.empty((0, len(names)), dtype=np.float64)
        return np.asarray([[row[name] for name in names] for row in rows], dtype=np.float64)

    def fit(
        self,
        training_data: Mapping[str, Sequence[Any]] | Any,
        *,
        benign_label: str = "Benign",
    ) -> "IsolationForestAnomalyModel":
        """Fit on benign rows only; ``Label`` is required but never a feature."""
        selected = select_features(training_data)
        if selected.labels is None:
            raise ValueError(
                f"Training data must include {LABEL_COLUMN!r} to verify benign rows."
            )
        if not selected.labels:
            raise ValueError("Cannot train on an empty dataset.")
        if not benign_label:
            raise ValueError("benign_label cannot be empty.")
        benign_indices = [
            index for index, label in enumerate(selected.labels) if label == benign_label
        ]
        if not benign_indices:
            raise ValueError(f"No records have the verified benign label {benign_label!r}.")

        self.training_records_seen_ = len(benign_indices)
        sample_limit = self.config.max_training_samples
        if sample_limit is not None and len(benign_indices) > sample_limit:
            benign_indices = sorted(
                random.Random(self.config.random_state).sample(benign_indices, sample_limit)
            )
        self.training_records_used_ = len(benign_indices)
        self.benign_label_ = benign_label

        benign_features = {
            name: [values[index] for index in benign_indices]
            for name, values in selected.features.items()
        }
        preprocessor = FittedFeaturePreprocessor()
        training_rows = preprocessor.fit_transform(benign_features)
        feature_names = preprocessor.feature_names_out_
        matrix = self._rows_to_matrix(training_rows, feature_names)
        if matrix.shape[0] == 0:
            raise ValueError("Cannot fit Isolation Forest on an empty dataset.")
        if matrix.shape[1] == 0:
            raise ValueError("No usable features remain after preprocessing.")

        estimator = IsolationForest(
            n_estimators=self.config.n_estimators,
            max_samples=self.config.max_samples,
            max_features=self.config.max_features,
            contamination=self.config.contamination,
            bootstrap=self.config.bootstrap,
            random_state=self.config.random_state,
            n_jobs=self.config.n_jobs,
        )
        estimator.fit(matrix)

        self.preprocessor = preprocessor
        self.estimator = estimator
        self.feature_names_in_ = feature_names
        return self

    def _require_fitted(self) -> tuple[IsolationForest, FittedFeaturePreprocessor]:
        if self.estimator is None or self.preprocessor is None:
            raise RuntimeError("Isolation Forest has not been trained or loaded.")
        return self.estimator, self.preprocessor

    @staticmethod
    def _event_ids(data: Mapping[str, Sequence[Any]] | Any, row_count: int) -> list[Any]:
        if isinstance(data, Mapping):
            ids = data.get("event_id")
        else:
            columns = getattr(data, "columns", ())
            ids = data["event_id"] if "event_id" in columns else None
        if ids is None:
            return [None] * row_count
        values = list(ids)
        if len(values) != row_count:
            raise ValueError("event_id row count does not match feature rows.")
        return values

    def predict(self, data: Mapping[str, Sequence[Any]] | Any) -> list[dict[str, Any]]:
        """Return stable detection records; no training or refitting occurs."""
        estimator, preprocessor = self._require_fitted()
        selected = select_features(data)
        if not selected.feature_names:
            raise ValueError("Input contains no selectable features.")
        if selected.features:
            row_count = len(next(iter(selected.features.values())))
        else:
            row_count = 0
        event_ids = self._event_ids(data, row_count)
        if row_count == 0:
            return []

        rows = preprocessor.transform(selected.features)
        matrix = self._rows_to_matrix(rows, self.feature_names_in_)
        decision_scores = estimator.decision_function(matrix)
        anomaly_scores = -decision_scores
        return [
            {
                "event_id": event_ids[index],
                "anomaly_score": float(score),
                "is_anomaly": bool(score > self.config.score_threshold),
                "model_version": self.config.model_version,
            }
            for index, score in enumerate(anomaly_scores)
        ]

    def save(self, artifact_path: str | Path, *, overwrite: bool = False) -> Path:
        """Persist the estimator, fitted preprocessing, feature order, and config."""
        self._require_fitted()
        target = Path(artifact_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing model artifact: {target}")
        target_resolved = target.resolve()
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                prefix=f".{target.name}.",
                suffix=".tmp",
                dir=target.parent,
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
            joblib.dump(self, temporary_path)
            if target.exists() and not overwrite:
                raise FileExistsError(
                    f"Refusing to overwrite existing model artifact: {target}"
                )
            os.replace(temporary_path, target_resolved)
            return target_resolved
        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink()

    @classmethod
    def load(cls, artifact_path: str | Path) -> "IsolationForestAnomalyModel":
        """Load a trusted local joblib artifact; never load untrusted files."""
        artifact = Path(artifact_path)
        if not artifact.is_file():
            raise FileNotFoundError(f"Model artifact not found: {artifact}")
        loaded = joblib.load(artifact)
        if not isinstance(loaded, cls) or not loaded.is_fitted:
            raise ValueError(f"Invalid or unfitted LeakLens model artifact: {artifact}")
        return loaded

    def metadata(self) -> dict[str, Any]:
        """Return serializable model settings and fitted feature metadata."""
        self._require_fitted()
        assert self.preprocessor is not None
        return {
            "model_version": self.config.model_version,
            "config": asdict(self.config),
            "benign_label": self.benign_label_,
            "training_records_seen": self.training_records_seen_,
            "training_records_used": self.training_records_used_,
            "features": list(self.feature_names_in_),
            "constant_features": list(self.preprocessor.constant_features_),
            "all_missing_features": list(self.preprocessor.all_missing_features_),
            "redundant_features": dict(self.preprocessor.redundant_features_),
        }

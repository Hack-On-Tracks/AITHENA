"""Train-fitted numeric preprocessing for selected network-flow features."""

from collections.abc import Mapping, Sequence
from math import isfinite
from typing import Any

import numpy as np
import pandas as pd


FeatureColumns = Mapping[str, Sequence[Any]]


def _materialize_columns(data: FeatureColumns) -> dict[str, list[Any]]:
    if not isinstance(data, Mapping):
        raise TypeError("Expected selected features as a column mapping.")
    columns = {name: list(values) for name, values in data.items()}
    lengths = {len(values) for values in columns.values()}
    if len(lengths) > 1:
        raise ValueError("Input columns have inconsistent row counts.")
    return columns


def _finite_numeric_values(values: Sequence[Any], column: str) -> list[float | None]:
    result: list[float | None] = []
    for value in values:
        is_missing = pd.isna(value)
        if not isinstance(is_missing, (bool, np.bool_)):
            raise ValueError(f"Feature {column!r} contains a non-scalar value.")
        if is_missing:
            result.append(None)
            continue
        if isinstance(value, bool):
            raise ValueError(f"Feature {column!r} contains a boolean value.")
        try:
            numeric_value = float(value)
        except (TypeError, ValueError, OverflowError) as error:
            raise ValueError(
                f"Feature {column!r} contains a non-numeric value: {value!r}."
            ) from error
        result.append(numeric_value if isfinite(numeric_value) else None)
    return result


def _finite_median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return ordered[midpoint - 1] / 2 + ordered[midpoint] / 2


class FittedFeaturePreprocessor:
    """Median-impute and remove train-constant or exactly duplicated columns.

    Call ``fit`` with training features only. Use the fitted instance's
    ``transform`` for validation, test, and inference data so no statistics
    are learned from those later datasets.
    """

    def __init__(self) -> None:
        self.input_features_: tuple[str, ...] = ()
        self.feature_names_out_: tuple[str, ...] = ()
        self.medians_: dict[str, float] = {}
        self.constant_features_: tuple[str, ...] = ()
        self.all_missing_features_: tuple[str, ...] = ()
        self.redundant_features_: dict[str, str] = {}
        self._is_fitted = False

    def fit(self, training_features: FeatureColumns) -> "FittedFeaturePreprocessor":
        self._is_fitted = False
        columns = _materialize_columns(training_features)
        if not columns:
            raise ValueError("Cannot fit preprocessing without feature columns.")
        row_count = len(next(iter(columns.values())))
        if row_count == 0:
            raise ValueError("Cannot fit preprocessing on an empty dataset.")

        self.input_features_ = tuple(columns)
        cleaned = {
            name: _finite_numeric_values(values, name)
            for name, values in columns.items()
        }
        self.medians_ = {}
        self.all_missing_features_ = ()
        self.constant_features_ = ()
        self.redundant_features_ = {}

        all_missing: list[str] = []
        constants: list[str] = []
        usable: list[str] = []
        imputed_training: dict[str, tuple[float, ...]] = {}

        for name in self.input_features_:
            observed = [value for value in cleaned[name] if value is not None]
            if not observed:
                all_missing.append(name)
                continue
            column_median = _finite_median(observed)
            self.medians_[name] = column_median
            imputed = tuple(
                column_median if value is None else value for value in cleaned[name]
            )
            imputed_training[name] = imputed
            if all(value == imputed[0] for value in imputed[1:]):
                constants.append(name)
            else:
                usable.append(name)

        retained: list[str] = []
        seen_columns: dict[tuple[float, ...], str] = {}
        for name in usable:
            values = imputed_training[name]
            duplicate_of = seen_columns.get(values)
            if duplicate_of is None:
                seen_columns[values] = name
                retained.append(name)
            else:
                self.redundant_features_[name] = duplicate_of

        self.all_missing_features_ = tuple(all_missing)
        self.constant_features_ = tuple(constants)
        self.feature_names_out_ = tuple(retained)
        self._is_fitted = True
        return self

    def transform(self, features: FeatureColumns) -> list[dict[str, float]]:
        if not self._is_fitted:
            raise RuntimeError("Preprocessor must be fitted before transform().")
        columns = _materialize_columns(features)
        missing = [name for name in self.input_features_ if name not in columns]
        if missing:
            raise ValueError("Missing fitted feature columns: " + ", ".join(missing))
        cleaned = {
            name: _finite_numeric_values(columns[name], name)
            for name in self.input_features_
        }
        row_count = len(next(iter(cleaned.values()))) if cleaned else 0
        return [
            {
                name: (
                    self.medians_[name]
                    if cleaned[name][row] is None
                    else float(cleaned[name][row])
                )
                for name in self.feature_names_out_
            }
            for row in range(row_count)
        ]

    def fit_transform(self, training_features: FeatureColumns) -> list[dict[str, float]]:
        """Fit only on the supplied training set and return its transformed rows."""
        return self.fit(training_features).transform(training_features)

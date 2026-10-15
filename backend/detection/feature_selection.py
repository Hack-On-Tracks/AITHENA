"""Select dataset-confirmed numeric flow features without exposing labels."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


REQUIRED_FEATURES = (
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packets Length Total",
    "Bwd Packets Length Total",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "SYN Flag Count",
    "RST Flag Count",
    "FIN Flag Count",
    "ACK Flag Count",
)

OPTIONAL_FEATURES = (
    "Packet Length Mean",
    "Packet Length Std",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    "Active Mean",
    "Idle Mean",
    "Protocol",
)

LABEL_COLUMN = "Label"


class MissingFeatureColumnsError(ValueError):
    """Raised when required dataset feature columns are missing."""


@dataclass(frozen=True)
class FeatureSelectionResult:
    """Selected numeric feature columns and separately retained labels."""

    features: dict[str, list[Any]]
    labels: list[Any] | None
    feature_names: tuple[str, ...]
    excluded_optional_features: tuple[str, ...]


def _columns_from_table(
    data: Mapping[str, Sequence[Any]] | Any,
) -> dict[str, list[Any]]:
    if isinstance(data, Mapping):
        return {name: list(values) for name, values in data.items()}

    columns = getattr(data, "columns", None)
    if columns is None:
        raise TypeError("Expected a column mapping or a dataframe-like object.")
    return {
        str(name): list(data[name].tolist())
        if callable(getattr(data[name], "tolist", None))
        else list(data[name])
        for name in columns
    }


def select_features(
    data: Mapping[str, Sequence[Any]] | Any,
) -> FeatureSelectionResult:
    """Select confirmed candidate columns and keep ``Label`` outside features.

    All 15 required features were confirmed in the extracted Parquet schemas.
    Optional candidates are selected when present and otherwise reported in
    ``excluded_optional_features``.
    """
    columns = _columns_from_table(data)
    missing_required = [name for name in REQUIRED_FEATURES if name not in columns]
    if missing_required:
        raise MissingFeatureColumnsError(
            "Missing required feature columns: " + ", ".join(missing_required)
        )

    selected_names = REQUIRED_FEATURES + tuple(
        name for name in OPTIONAL_FEATURES if name in columns
    )
    selected = {name: columns[name] for name in selected_names}
    lengths = {len(values) for values in columns.values()}
    if len(lengths) > 1:
        raise ValueError("Input columns have inconsistent row counts.")

    return FeatureSelectionResult(
        features=selected,
        labels=columns.get(LABEL_COLUMN),
        feature_names=selected_names,
        excluded_optional_features=tuple(
            name for name in OPTIONAL_FEATURES if name not in columns
        ),
    )

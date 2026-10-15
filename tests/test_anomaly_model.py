import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from backend.detection.anomaly_model import (
    IsolationForestAnomalyModel,
    IsolationForestConfig,
)
from backend.detection.detection_service import evaluate_records
from backend.detection.feature_selection import OPTIONAL_FEATURES, REQUIRED_FEATURES


FEATURE_NAMES = REQUIRED_FEATURES + OPTIONAL_FEATURES


def make_data(labels=("Benign", "Benign", "Benign", "Benign", "DDoS", "DDoS")):
    data = {
        name: [float(index * (offset + 1) + offset) for index in range(len(labels))]
        for offset, name in enumerate(FEATURE_NAMES)
    }
    data["Label"] = list(labels)
    return data


def make_config(**overrides):
    values = {
        "n_estimators": 16,
        "random_state": 17,
        "max_training_samples": 100,
        "model_version": "test-model",
    }
    values.update(overrides)
    return IsolationForestConfig(**values)


class IsolationForestModelTests(unittest.TestCase):
    def test_fit_uses_verified_benign_rows_and_excludes_label(self):
        model = IsolationForestAnomalyModel(make_config(max_training_samples=2))
        model.fit(make_data())
        self.assertTrue(model.is_fitted)
        self.assertEqual(model.training_records_seen_, 4)
        self.assertEqual(model.training_records_used_, 2)
        self.assertNotIn("Label", model.feature_names_in_)
        self.assertEqual(model.benign_label_, "Benign")

    def test_fit_requires_labels_and_verified_benign_training_rows(self):
        data = make_data(("DDoS", "DDoS"))
        with self.assertRaisesRegex(ValueError, "No records have the verified benign"):
            IsolationForestAnomalyModel(make_config()).fit(data)
        del data["Label"]
        with self.assertRaisesRegex(ValueError, "'Label'"):
            IsolationForestAnomalyModel(make_config()).fit(data)

    def test_predict_returns_consistent_results_with_optional_event_id(self):
        model = IsolationForestAnomalyModel(make_config()).fit(make_data())
        prediction_data = {
            name: make_data()[name][-2:]
            for name in FEATURE_NAMES
        }
        prediction_data["event_id"] = ["flow-1", "flow-2"]
        results = model.predict(prediction_data)
        self.assertEqual([result["event_id"] for result in results], ["flow-1", "flow-2"])
        self.assertTrue(all("anomaly_score" in result for result in results))
        self.assertTrue(all("is_anomaly" in result for result in results))
        self.assertTrue(all(r["model_version"] == "test-model" for r in results))

    def test_anomaly_score_is_negative_decision_function(self):
        model = IsolationForestAnomalyModel(make_config()).fit(make_data())
        prediction_data = {
            name: make_data()[name][-2:]
            for name in FEATURE_NAMES
        }
        results = model.predict(prediction_data)
        selected = {
            name: prediction_data[name]
            for name in FEATURE_NAMES
        }
        transformed = model.preprocessor.transform(selected)
        matrix = model._rows_to_matrix(transformed, model.feature_names_in_)
        expected = -model.estimator.decision_function(matrix)
        np.testing.assert_allclose(
            [row["anomaly_score"] for row in results], expected
        )
        self.assertEqual(
            [row["is_anomaly"] for row in results],
            [score > model.config.score_threshold for score in expected],
        )

    def test_threshold_is_configurable(self):
        data = make_data()
        model = IsolationForestAnomalyModel(
            make_config(score_threshold=1e6)
        ).fit(data)
        results = model.predict({name: values[:1] for name, values in data.items() if name != "Label"})
        self.assertFalse(results[0]["is_anomaly"])

    def test_missing_required_and_invalid_values_fail_safely(self):
        model = IsolationForestAnomalyModel(make_config()).fit(make_data())
        incomplete = make_data()
        del incomplete[REQUIRED_FEATURES[0]]
        with self.assertRaisesRegex(ValueError, "Missing required feature"):
            model.predict(incomplete)
        invalid = {name: values[:1] for name, values in make_data().items()}
        invalid["Flow Duration"] = ["not-a-number"]
        with self.assertRaisesRegex(ValueError, "non-numeric"):
            model.predict(invalid)

    def test_pandas_nullable_missing_values_are_imputed(self):
        data = make_data()
        data["Flow Duration"][0] = pd.NA
        model = IsolationForestAnomalyModel(make_config()).fit(data)
        inference = {
            name: values[:1]
            for name, values in data.items()
            if name != "Label"
        }
        self.assertEqual(len(model.predict(inference)), 1)

    def test_empty_inference_returns_empty_and_empty_training_is_rejected(self):
        model = IsolationForestAnomalyModel(make_config()).fit(make_data())
        empty = {name: [] for name in FEATURE_NAMES}
        self.assertEqual(model.predict(empty), [])
        with self.assertRaisesRegex(ValueError, "empty dataset"):
            IsolationForestAnomalyModel(make_config()).fit(make_data(()))

    def test_untrained_prediction_fails_explicitly(self):
        with self.assertRaisesRegex(RuntimeError, "has not been trained"):
            IsolationForestAnomalyModel(make_config()).predict(
                {name: [1] for name in FEATURE_NAMES}
            )

    def test_fitted_preprocessing_is_reused_after_save_and_load(self):
        data = make_data()
        data["Flow Duration"][0] = None
        model = IsolationForestAnomalyModel(make_config()).fit(data)
        inference = {
            name: [values[0]]
            for name, values in data.items()
            if name != "Label"
        }
        expected = model.predict(inference)
        self.assertIn("Flow Duration", model.preprocessor.medians_)
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "model.joblib"
            saved = model.save(artifact)
            loaded = IsolationForestAnomalyModel.load(saved)
            actual = loaded.predict(inference)
            self.assertEqual(actual, expected)
            self.assertEqual(
                loaded.preprocessor.medians_["Flow Duration"],
                model.preprocessor.medians_["Flow Duration"],
            )

    def test_save_refuses_to_overwrite_existing_artifact(self):
        model = IsolationForestAnomalyModel(make_config()).fit(make_data())
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "model.joblib"
            model.save(artifact)
            with self.assertRaises(FileExistsError):
                model.save(artifact)

    def test_evaluation_labels_are_separate_from_model_features(self):
        model = IsolationForestAnomalyModel(make_config()).fit(make_data())
        records = {
            name: values[-2:]
            for name, values in make_data().items()
            if name != "Label"
        }
        result = evaluate_records(model, records, ["DDoS", "Benign"])
        self.assertEqual(result["evaluation_records"], 2)
        self.assertNotIn("Label", model.feature_names_in_)
        self.assertEqual(sum(map(sum, result["confusion_matrix"]["rows_actual_columns_predicted"])), 2)


if __name__ == "__main__":
    unittest.main()

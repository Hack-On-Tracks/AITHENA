import unittest
from math import isfinite

from backend.detection.feature_selection import (
    OPTIONAL_FEATURES,
    REQUIRED_FEATURES,
    MissingFeatureColumnsError,
    select_features,
)
from backend.detection.preprocessing import FittedFeaturePreprocessor


def make_candidate_table(row_count=2):
    data = {
        name: [float(index + offset) for index in range(row_count)]
        for offset, name in enumerate(REQUIRED_FEATURES + OPTIONAL_FEATURES)
    }
    data["Label"] = ["Benign", "DDoS"][:row_count]
    return data


class FeatureSelectionTests(unittest.TestCase):
    def test_selects_all_schema_confirmed_candidates_in_order(self):
        selected = select_features(make_candidate_table())
        self.assertEqual(
            selected.feature_names, REQUIRED_FEATURES + OPTIONAL_FEATURES
        )
        self.assertEqual(set(selected.features), set(selected.feature_names))
        self.assertNotIn("Label", selected.features)
        self.assertEqual(selected.excluded_optional_features, ())

    def test_preserves_labels_separately(self):
        selected = select_features(make_candidate_table())
        self.assertEqual(selected.labels, ["Benign", "DDoS"])
        self.assertNotIn("Label", selected.feature_names)

    def test_absent_optional_candidates_are_reported_and_skipped(self):
        table = make_candidate_table()
        for name in OPTIONAL_FEATURES:
            del table[name]
        selected = select_features(table)
        self.assertEqual(selected.feature_names, REQUIRED_FEATURES)
        self.assertEqual(selected.excluded_optional_features, OPTIONAL_FEATURES)

    def test_missing_required_column_fails_explicitly(self):
        table = make_candidate_table()
        del table[REQUIRED_FEATURES[0]]
        with self.assertRaisesRegex(MissingFeatureColumnsError, REQUIRED_FEATURES[0]):
            select_features(table)

    def test_empty_table_is_selectable_but_cannot_fit(self):
        selected = select_features(make_candidate_table(row_count=0))
        self.assertEqual(selected.labels, [])
        with self.assertRaisesRegex(ValueError, "empty dataset"):
            FittedFeaturePreprocessor().fit(selected.features)

    def test_inconsistent_input_column_lengths_are_rejected(self):
        table = make_candidate_table()
        table["Label"].append("unexpected")
        with self.assertRaisesRegex(ValueError, "inconsistent row counts"):
            select_features(table)


class PreprocessingTests(unittest.TestCase):
    def test_missing_and_infinite_values_are_median_imputed(self):
        training = {
            "varying": [1.0, None, 5.0, float("inf"), float("-inf")],
            "constant": [9, 9, 9, 9, 9],
        }
        processor = FittedFeaturePreprocessor()
        transformed = processor.fit_transform(training)
        self.assertEqual(processor.medians_["varying"], 3.0)
        self.assertEqual([row["varying"] for row in transformed], [1, 3, 5, 3, 3])

    def test_constant_and_exact_duplicate_columns_are_detected(self):
        processor = FittedFeaturePreprocessor().fit(
            {
                "primary": [1, 2, 3],
                "duplicate": [1, 2, 3],
                "constant": [7, 7, 7],
                "all_missing": [None, float("nan"), float("inf")],
            }
        )
        self.assertEqual(processor.feature_names_out_, ("primary",))
        self.assertEqual(processor.constant_features_, ("constant",))
        self.assertEqual(processor.redundant_features_, {"duplicate": "primary"})
        self.assertEqual(processor.all_missing_features_, ("all_missing",))

    def test_missing_inference_column_is_not_filled_with_zero(self):
        processor = FittedFeaturePreprocessor().fit({"feature": [1, 2]})
        with self.assertRaisesRegex(ValueError, "Missing fitted feature columns"):
            processor.transform({})

    def test_fit_statistics_are_reused_for_inference(self):
        processor = FittedFeaturePreprocessor()
        train_rows = processor.fit_transform({"feature": [1, None, 3]})
        test_rows = processor.transform({"feature": [None, 100]})
        self.assertEqual([row["feature"] for row in train_rows], [1, 2, 3])
        self.assertEqual([row["feature"] for row in test_rows], [2, 100])
        self.assertEqual(processor.medians_["feature"], 2)

    def test_median_remains_finite_for_large_finite_values(self):
        processor = FittedFeaturePreprocessor().fit(
            {"feature": [1e308, 1.7e308]}
        )
        self.assertTrue(isfinite(processor.medians_["feature"]))

    def test_label_data_is_not_accepted_by_preprocessor(self):
        processor = FittedFeaturePreprocessor()
        with self.assertRaisesRegex(ValueError, "non-numeric"):
            processor.fit({"Label": ["Benign", "DDoS"]})

    def test_unfitted_transform_fails_explicitly(self):
        with self.assertRaisesRegex(RuntimeError, "must be fitted"):
            FittedFeaturePreprocessor().transform({"feature": [1]})


if __name__ == "__main__":
    unittest.main()

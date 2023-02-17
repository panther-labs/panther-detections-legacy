from panther_sdk import testing
from panther_detections.utils import legacy_utils


class TestLegacyUtils(testing.PantherPythonFilterTestCase):
    def test_deep_get(self) -> None:
        evt = {"a": {"b": "targeted-value"}}

        self.assertEqual(legacy_utils.deep_get(evt, "a", "b"), "targeted-value")
        self.assertEqual(legacy_utils.deep_get(evt, "a", "c"), None)
        self.assertEqual(legacy_utils.deep_get(evt, "a", "c", default="DEFAULT"), "DEFAULT")

    def test_pattern_match_list(self) -> None:
        self.assertEqual(
            legacy_utils.pattern_match_list("abc", ["a", "b", "y", "z"]), False
            )

        self.assertEqual(
            legacy_utils.pattern_match_list("abcd", ["a", "b", "y", "z", "abc*"]), True
            )
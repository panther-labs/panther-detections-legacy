import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import zoom


class TestRulesUserPromotedToPrivilegedRole(unittest.TestCase):
    def test_user_promoted_to_privileged_role(self) -> None:
        name_override = "Override Name"
        rule = zoom.rules.user_promoted_to_privileged_role(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_user_promoted_to_privileged_role_title(self) -> None:
        rule = zoom.rules.user_promoted_to_privileged_role()
        evt = PantherEvent(json.loads(zoom.sample_logs.user_promoted_to_privileged_role_admin_promotion_event))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "Zoom: [homer.simpson@duff.io]'s role was changed from [User] to [Co-Owner] by [admin@duff.io].")

import typing
import unittest

from panther_sdk import query

from panther_detections.providers import okta


class TestQueries(unittest.TestCase):
    def test_queries(self) -> None:
        name_override = "Override Name"
        override = query.QueryOverrides(name=name_override)

        datalakes: typing.List[typing.Literal["snowflake", "athena"]] = [
            "snowflake",
            "athena",
        ]

        for datalake in datalakes:
            self.assertEqual(
                okta.queries.activity_audit(datalake=datalake, overrides=override).name,
                name_override,
            )
            self.assertEqual(
                okta.queries.session_id_audit(
                    datalake=datalake, overrides=override
                ).name,
                name_override,
            )
            self.assertEqual(
                okta.queries.admin_access_granted(
                    datalake=datalake, overrides=override
                ).name,
                name_override,
            )
            self.assertEqual(
                okta.queries.mfa_password_reset_audit(
                    datalake=datalake, overrides=override
                ).name,
                name_override,
            )
            self.assertEqual(
                okta.queries.support_access(datalake=datalake, overrides=override).name,
                name_override,
            )

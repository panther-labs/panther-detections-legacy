import typing
import unittest

from panther_sdk import query

from panther_detections.providers import okta


class TestQueries(unittest.TestCase):
    def test_queries(self) -> None:
        datalakes: typing.List[typing.Literal["snowflake", "athena"]] = [
            "snowflake",
            "athena",
        ]

        for datalake in datalakes:
            q = okta.queries.activity_audit(datalake=datalake)
            self.assertNotEqual(q.sql, "")
            q = okta.queries.session_id_audit(datalake=datalake)
            self.assertNotEqual(q.sql, "")
            q = okta.queries.admin_access_granted(datalake=datalake)
            self.assertNotEqual(q.sql, "")
            q = okta.queries.mfa_password_reset_audit(datalake=datalake)
            self.assertNotEqual(q.sql, "")
            q = okta.queries.support_access(datalake=datalake)
            self.assertNotEqual(q.sql, "")

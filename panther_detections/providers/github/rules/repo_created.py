from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["repo_created"]


def repo_created(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Detects when a repository is created."""

    def _title(event: PantherEvent) -> str:
        return f"Repository [{event.get('repo', '<UNKNOWN_REPO>')}] created."

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GitHub Repository Created",
        rule_id="Github.Repo.Created",
        log_types=[schema.LogTypeGitHubAudit],
        severity=detection.SeverityInfo,
        description="Detects when a repository is created.",
        tags=rule_tags(),
        # reports=,
        # reference=,
        # runbook=,
        alert_title=_title,
        # summary_attrs=,
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[match_filters.deep_equal("action", "repo.create")],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="GitHub - Repo Created",
                    expect_match=True,
                    data=sample_logs.repo_created_github___repo_created,
                ),
                detection.JSONUnitTest(
                    name="GitHub - Repo Archived",
                    expect_match=False,
                    data=sample_logs.repo_created_github___repo_archived,
                ),
            ]
        ),
    )

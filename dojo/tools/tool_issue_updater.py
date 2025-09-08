from dojo.celery import app
from dojo.decorators import dojo_async_task, dojo_model_from_id, dojo_model_to_id
from dojo.tools.api_sonarqube.parser import SCAN_SONARQUBE_API
from dojo.tools.api_snyk.parser import SCAN_SNYK_API


def async_tool_issue_update(finding, *args, **kwargs):
    if is_tool_issue_updater_needed(finding):
        tool_issue_updater(finding)


def is_tool_issue_updater_needed(finding, *args, **kwargs):
    test_type = finding.test.test_type

    if test_type.name == SCAN_SNYK_API:
        return True

    if test_type.name == SCAN_SONARQUBE_API:
        return True

    return False


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def tool_issue_updater(finding, *args, **kwargs):

    test_type = finding.test.test_type

    if test_type.name == SCAN_SONARQUBE_API:
        from dojo.tools.api_sonarqube.updater import SonarQubeApiUpdater
        SonarQubeApiUpdater().update_sonarqube_finding(finding)

    if test_type.name == SCAN_SNYK_API:
        from dojo.tools.api_snyk.updater import SnykApiUpdater
        SnykApiUpdater().update_snyk_finding(finding)

@dojo_async_task
@app.task
def update_findings_from_source_issues(**kwargs):
    from dojo.tools.api_sonarqube.updater_from_source import SonarQubeApiUpdaterFromSource
    from dojo.tools.api_snyk.updater_from_source import SnykApiUpdaterFromSource

    # TODO DIMI - smart imports and better handling here

    findings = SonarQubeApiUpdaterFromSource().get_findings_to_update()

    for finding in findings:
        SonarQubeApiUpdaterFromSource().update(finding)

    findings = SnykApiUpdaterFromSource().get_findings_to_update()

    for finding in findings:
        SnykApiUpdaterFromSource().update(finding)

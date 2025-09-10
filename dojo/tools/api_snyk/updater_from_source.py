import logging

from django.utils import timezone

import dojo.risk_acceptance.helper as ra_helper
from dojo.models import Finding, Risk_Acceptance

from .importer import SnykApiImporter

logger = logging.getLogger(__name__)


class SnykApiUpdaterFromSource:
    """
    The responsibility of this class is to update the Finding status if current Snyk issue status doesn't match.

    This way, findings will be updated based on Snyk information when Snyk is updated manually and
    already imported in DefectDojo.
    """

    @staticmethod
    def get_findings_to_update():
        findings = Finding.objects.filter(
            snyk_issue__isnull=False,
            active=True,
        ).select_related("snyk_issue")
        logger.debug(f"Found {findings.count()} findings with Snyk issues to potentially update")
        return findings

    def update(self, finding):
        snyk_issue = finding.snyk_issue
        if not snyk_issue:
            logger.debug(f"Finding {finding.id} has no associated Snyk issue, skipping update")
            return

        logger.debug(f"Checking Snyk status for finding {finding.id} with issue {snyk_issue.key}")

        try:
            client, config = SnykApiImporter.prepare_client(finding.test)
            # we don't care about config, each finding knows which config was used
            # during import

            org_id = config.service_key_1
            logger.debug(f"Using organization ID: {org_id}")

            issue = client.get_issue(org_id, snyk_issue.key)

            if not issue:  # Issue could have disappeared in Snyk
                logger.warning(f"Issue {snyk_issue.key} not found in Snyk (may have been deleted)")
                return

            current_status = "IGNORED" if issue.get("ignored", False) else "OPEN"
            current_finding_status = self.get_snyk_status_for(finding)

            logger.debug(
                f"--> Snyk Current status: {current_status}. Finding status: {current_finding_status}",
            )

            if current_status != current_finding_status:
                logger.info(
                    f"Original Snyk issue '{snyk_issue}' has changed. Updating DefectDojo finding '{finding}'...",
                )
                self.update_finding_status(finding, current_status, issue)
            else:
                logger.debug("No status change needed - Snyk and DefectDojo are in sync")

        except Exception as e:
            logger.warning(f"Failed to check Snyk issue {snyk_issue.key}: {str(e)}")
            logger.exception("Exception details for Snyk status check failure")

    @staticmethod
    def get_snyk_status_for(finding):
        target_status = None
        if finding.false_p:
            target_status = "IGNORED"
        elif finding.mitigated or finding.is_mitigated:
            target_status = "IGNORED"
        elif finding.risk_accepted:
            target_status = "IGNORED"
        elif finding.active:
            target_status = "OPEN"

        logger.debug(f"Mapped finding status to Snyk status: {target_status} for finding {finding.id}")
        return target_status

    @staticmethod
    def update_finding_status(finding, snyk_status, issue_data=None):
        logger.debug(f"Updating finding {finding.id} to match Snyk status: {snyk_status}")

        if snyk_status == "OPEN":
            logger.debug("Setting finding to active/open status")
            finding.active = True
            finding.verified = True
            finding.false_p = False
            finding.mitigated = None
            finding.is_mitigated = False
            ra_helper.remove_finding.from_any_risk_acceptance(finding)

        elif snyk_status == "IGNORED":
            # Try to determine the specific reason for ignoring
            ignore_reason = None
            if issue_data and "ignoreReasons" in issue_data:
                ignore_reasons = issue_data["ignoreReasons"]
                if ignore_reasons:
                    ignore_reason = ignore_reasons[0].get("reason", "").lower()
                    logger.debug(f"Found specific ignore reason: {ignore_reason}")

            if ignore_reason == "false-positive" or ignore_reason == "not-vulnerable":
                logger.debug("Setting finding as false positive")
                finding.active = False
                finding.verified = False
                finding.false_p = True
                finding.mitigated = None
                finding.is_mitigated = False
                ra_helper.remove_finding.from_any_risk_acceptance(finding)

            elif ignore_reason == "fixed":
                logger.debug("Setting finding as mitigated/fixed")
                finding.active = False
                finding.verified = True
                finding.false_p = False
                finding.mitigated = timezone.now()
                finding.is_mitigated = True
                ra_helper.remove_finding.from_any_risk_acceptance(finding)

            elif ignore_reason == "wont-fix" or ignore_reason == "no-fix":
                logger.debug("Creating risk acceptance for finding")
                finding.active = False
                finding.verified = True
                finding.false_p = False
                finding.mitigated = None
                finding.is_mitigated = False
                Risk_Acceptance.objects.create(
                    owner=finding.reporter,
                ).accepted_findings.set([finding])

            else:
                # Generic ignore - treat as accepted risk
                logger.debug("Creating generic risk acceptance for ignored finding")
                finding.active = False
                finding.verified = True
                finding.false_p = False
                finding.mitigated = None
                finding.is_mitigated = False
                Risk_Acceptance.objects.create(
                    owner=finding.reporter,
                ).accepted_findings.set([finding])

        finding.save(issue_updater_option=False, dedupe_option=False)
        logger.info(f"Successfully updated finding {finding.id} status to match Snyk")
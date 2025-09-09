import logging

from dojo.models import Snyk_Issue_Transition

from .importer import SnykApiImporter
from .api_client import IGNORE_TYPE

logger = logging.getLogger(__name__)


class SnykApiUpdater:
    """
    This class updates in Snyk, a Snyk issue previously imported as a DefectDojo Finding.
    This class maps the finding status to a Snyk issue status and later on it transitions the issue
    properly to a consistent status.
    This way, findings marked as resolved, false positive or accepted in DefectDojo won't reappear
    in future imports of Snyk Scanner.
    """

    @staticmethod
    def get_snyk_status_for(finding):
        target_status = None
        if finding.false_p:
            target_status = "IGNORED / FALSE-POSITIVE"
        elif finding.mitigated or finding.is_mitigated:
            target_status = "IGNORED / FIXED"
        elif finding.risk_accepted:
            target_status = "IGNORED / WONTFIX"
        elif finding.active:
            target_status = "OPEN"

        logger.debug(f"Mapped finding status to Snyk status: {target_status} for finding {finding.id}")
        return target_status

    def update_snyk_finding(self, finding):
        snyk_issue = finding.snyk_issue
        if not snyk_issue:
            logger.debug(f"Finding {finding.id} has no associated Snyk issue, skipping update")
            return

        logger.debug(
            f"Checking if finding '{finding}' needs to be updated in Snyk",
        )

        try:
            client, _ = SnykApiImporter.prepare_client(finding.test)
            # we don't care about config, each finding knows which config was used
            # during import

            target_status = self.get_snyk_status_for(finding)

            # Get the organization ID from the test configuration
            config = finding.test.api_scan_configuration
            if not config:
                logger.debug("No test-specific config, trying product configurations")
                # Try to get from product configuration
                product = finding.test.engagement.product
                snyk_configs = product.product_api_scan_configuration_set.filter(
                    product=product,
                    tool_configuration__tool_type__name="Snyk",
                )
                if snyk_configs.count() >= 1:
                    config = snyk_configs.first()
                    logger.debug(f"Using product config {config.id}")
                else:
                    logger.warning(f"No Snyk API configuration found for finding {finding}")
                    return

            org_id = config.service_key_1
            logger.debug(f"Using organization ID: {org_id}")

            issue = client.get_issue(org_id, snyk_issue.key)
            if issue:  # Issue could have disappeared in Snyk
                current_status = "IGNORED" if issue.get("attributes", {}).get("ignored", False) else "OPEN"

                logger.debug(
                    f"--> Snyk Current status: {current_status}. Current target status: {target_status}",
                )
                # TODO DIMI - replace with get methods for better handling
                issue_name = issue["attributes"]["key"]
                project = issue["relationships"]["scan_item"]["data"]["id"]
                org_name = client.get_id_to_org_mapping().get(org_id, "unknown_org")

                # Determine what action to take
                if target_status and target_status != current_status:
                    logger.info(
                        f"Updating finding '{finding}' in Snyk",
                    )

                    if target_status.startswith("IGNORED"):
                        # Map DefectDojo status to Snyk ignore reason
                        if "FALSE-POSITIVE" in target_status:
                            reason = IGNORE_TYPE.NOT_VULNERABLE.value
                            notes = "Marked as false positive in DefectDojo"
                        elif "FIXED" in target_status:
                            reason = IGNORE_TYPE.FIXED.value
                            notes = "Marked as fixed in DefectDojo"
                        elif "WONTFIX" in target_status:
                            reason = IGNORE_TYPE.WONT_FIX.value
                            notes = "Risk accepted in DefectDojo"
                        else:
                            reason = IGNORE_TYPE.OTHER.value
                            notes = "Ignored in DefectDojo"

                        logger.debug(f"Ignoring issue with reason: {reason}, notes: {notes}")
                        client.ignore_issue(org_name=org_name, project_id=project, issue_name=issue_name, reason=reason, notes=notes)
                        action = f"ignored ({reason})"
                    elif target_status == "OPEN" and current_status == "IGNORED":
                        logger.debug("Unignoring issue")
                        client.unignore_issue(org_name=org_name, project_id=project, issue_name=issue_name)
                        action = "unignored"
                    else:
                        action = "no action needed"

                    # Track DefectDojo has updated the Snyk issue
                    if action != "no action needed":
                        logger.debug(f"Creating transition record: {action}")
                        Snyk_Issue_Transition.objects.create(
                            snyk_issue=finding.snyk_issue,
                            finding_status=finding.status().replace(
                                "Risk Accepted", "Accepted",
                            ) if finding.status() else finding.status(),
                            snyk_status=current_status,
                            transitions=action,
                        )
                        logger.info(f"Successfully updated Snyk issue {snyk_issue.key} with action: {action}")
                else:
                    logger.debug("No status change needed - Snyk and DefectDojo are in sync")
            else:
                logger.warning(f"Issue {snyk_issue.key} not found in Snyk (may have been deleted)")

        except Exception as e:
            logger.warning(f"Failed to update Snyk issue {snyk_issue.key}: {str(e)}")
            logger.exception("Exception details for Snyk update failure")
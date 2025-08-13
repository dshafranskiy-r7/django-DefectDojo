import logging

from dojo.models import Snyk_Issue_Transition

from .importer import SnykApiImporter

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
        return target_status

    def update_snyk_finding(self, finding):
        snyk_issue = finding.snyk_issue
        if not snyk_issue:
            return

        logger.debug(
            f"Checking if finding '{finding}' needs to be updated in Snyk",
        )

        client, _ = SnykApiImporter.prepare_client(finding.test)
        # we don't care about config, each finding knows which config was used
        # during import

        target_status = self.get_snyk_status_for(finding)

        # Get the organization ID from the test configuration
        config = finding.test.api_scan_configuration
        if not config:
            # Try to get from product configuration
            product = finding.test.engagement.product
            snyk_configs = product.product_api_scan_configuration_set.filter(
                product=product,
                tool_configuration__tool_type__name="Snyk",
            )
            if snyk_configs.count() >= 1:
                config = snyk_configs.first()
            else:
                logger.warning(f"No Snyk API configuration found for finding {finding}")
                return

        org_id = config.service_key_1

        try:
            issue = client.get_issue(org_id, snyk_issue.key)
            if issue:  # Issue could have disappeared in Snyk
                current_status = "IGNORED" if issue.get("ignored", False) else "OPEN"

                logger.debug(
                    f"--> Snyk Current status: {current_status}. Current target status: {target_status}",
                )

                # Determine what action to take
                if target_status and target_status != current_status:
                    logger.info(
                        f"Updating finding '{finding}' in Snyk",
                    )

                    if target_status.startswith("IGNORED"):
                        # Map DefectDojo status to Snyk ignore reason
                        if "FALSE-POSITIVE" in target_status:
                            reason = "false-positive"
                            notes = "Marked as false positive in DefectDojo"
                        elif "FIXED" in target_status:
                            reason = "fixed"
                            notes = "Marked as fixed in DefectDojo"
                        elif "WONTFIX" in target_status:
                            reason = "wont-fix"
                            notes = "Risk accepted in DefectDojo"
                        else:
                            reason = "other"
                            notes = "Ignored in DefectDojo"

                        client.ignore_issue(org_id, snyk_issue.key, reason, notes)
                        action = f"ignored ({reason})"
                    elif target_status == "OPEN" and current_status == "IGNORED":
                        client.unignore_issue(org_id, snyk_issue.key)
                        action = "unignored"
                    else:
                        action = "no action needed"

                    # Track DefectDojo has updated the Snyk issue
                    if action != "no action needed":
                        Snyk_Issue_Transition.objects.create(
                            snyk_issue=finding.snyk_issue,
                            finding_status=finding.status().replace(
                                "Risk Accepted", "Accepted",
                            ) if finding.status() else finding.status(),
                            snyk_status=current_status,
                            transitions=action,
                        )

        except Exception as e:
            logger.warning(f"Failed to update Snyk issue {snyk_issue.key}: {str(e)}")
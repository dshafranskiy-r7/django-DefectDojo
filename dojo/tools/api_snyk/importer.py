import logging
import textwrap

from django.core.exceptions import ValidationError

from dojo.models import Finding, Snyk_Issue
from dojo.notifications.helper import create_notification

from .api_client import SnykAPI

logger = logging.getLogger(__name__)


class SnykApiImporter:
    """
    This class imports from Snyk all open issues related to the project or organization
    related to the test as findings.
    """

    def get_findings(self, filename, test):
        items = self.import_issues(test)
        return items

    @staticmethod
    def is_ignored(issue):
        """Check if the issue is ignored in Snyk."""
        ignored = issue.get("attributes", False).get("ignored", False)
        if ignored:
            logger.debug(
                f"Issue {issue.get('id', 'unknown')} is ignored in Snyk")
        return ignored

    @staticmethod
    def prepare_client(test):
        product = test.engagement.product
        logger.debug(
            f"Preparing Snyk client for test {test.id} in product '{product.name}' ({product.id})")

        if test.api_scan_configuration:
            config = test.api_scan_configuration
            logger.debug(
                f"Using test-specific API scan configuration: {config.id}")
            # Double check of config
            if config.product != product:
                msg = (
                    "Product API Scan Configuration and Product do not match. "
                    f'Product: "{product.name}" ({product.id}), config.product: "{config.product.name}" ({config.product.id})'
                )
                logger.error(msg)
                raise ValidationError(msg)
        else:
            logger.debug(
                "No test-specific configuration, searching for product configurations")
            snyk_configs = product.product_api_scan_configuration_set.filter(
                product=product,
                tool_configuration__tool_type__name="Snyk",
            )
            logger.debug(
                f"Found {snyk_configs.count()} Snyk configurations for product")

            if snyk_configs.count() == 1:
                config = snyk_configs.first()
                logger.debug(
                    f"Using single product API scan configuration: {config.id}")
            elif snyk_configs.count() > 1:
                msg = (
                    "More than one Product API Scan Configuration has been configured, but none of them has been "
                    "chosen. Please specify which one should be used. "
                    f'Product: "{product.name}" ({product.id})'
                )
                logger.error(msg)
                raise ValidationError(msg)
            else:
                msg = (
                    "There are no API Scan Configurations for this Product.\n"
                    "Please add at least one API Scan Configuration for Snyk to this Product. "
                    f'Product: "{product.name}" ({product.id})'
                )
                logger.error(msg)
                raise ValidationError(msg)

        logger.debug(
            f"Successfully prepared Snyk client with configuration {config.id}")
        return SnykAPI(tool_config=config.tool_configuration), config

    def import_issues(self, test):
        items = []

        try:
            logger.debug(f"Starting Snyk issue import for test {test.id}")
            client, config = self.prepare_client(test)

            # Get organization ID from service key 1
            org_id = config.service_key_1
            # Get project ID from service key 2 (optional)
            project_id = config.service_key_2 if config.service_key_2 else None

            logger.debug(
                f"Import configuration - org_id: {org_id}, project_id: {project_id}")

            # Get issues from Snyk
            issues = client.get_issues(org_id, project_id)
            logger.info(
                f"Found {len(issues)} issues for {'project ' + project_id if project_id else 'organization ' + org_id}",
            )

            org_mapping = client.get_id_to_org_mapping()

            for issue in issues:
                issue_id = issue.get("id")
                logger.debug(f"Processing issue: {issue_id}")

                # Skip ignored issues
                if self.is_ignored(issue):
                    logger.debug(f"Skipping ignored issue: {issue_id}")
                    continue

                key = issue["attributes"]["key"]
                project = issue["relationships"]["scan_item"]["data"]["id"]
                org_name = org_mapping.get(org_id, "unknown_org")

                issue_url = f"https://app.snyk.io/org/{org_name}/project/{project}#issue-{key}"

                # Get detailed issue information
                issue_title = issue.get("attributes", {}).get("title", "Unknown Snyk Issue")
                title = textwrap.shorten(text=issue_title, width=500)
                logger.debug(f"Issue title: {title}")

                # Extract vulnerability information from coordinates
                vuln_pkg = ""
                vuln_version = ""
                coordinates = issue.get("attributes", {}).get("coordinates", [])
                if coordinates and len(coordinates) > 0:
                    representations = coordinates[0].get("representations", [])
                    if representations and len(representations) > 0:
                        dependency = representations[0].get("dependency", {})
                        vuln_pkg = dependency.get("package_name", "")
                        vuln_version = dependency.get("package_version", "")

                # Get severity from effective_severity_level
                snyk_severity = issue.get("attributes", {}).get("effective_severity_level", "low")
                severity = self.convert_snyk_severity(snyk_severity)
                logger.debug(
                    f"Issue details - package: {vuln_pkg}, version: {vuln_version}, severity: {snyk_severity} -> {severity}")

                # Build description
                description_parts = []
                # Use title as description if no separate description field
                description_parts.append(issue_title)

                if vuln_pkg:
                    description_parts.append(f"Package: {vuln_pkg}")

                if vuln_version:
                    description_parts.append(f"Version: {vuln_version}")

                # Add exploit details if available
                exploit_details = issue.get("attributes", {}).get("exploit_details", {})
                if exploit_details:
                    sources = exploit_details.get("sources", [])
                    if sources:
                        description_parts.append(f"Exploit Sources: {', '.join(sources)}")

                description = "\n\n".join(
                    description_parts) if description_parts else "No description available"
                logger.debug(
                    f"Built description with {len(description_parts)} parts")

                # Build references
                references = ""
                if issue_url:
                    references += f"[Snyk Issue]({issue_url})\n"
                    logger.debug(f"Added issue URL to references: {issue_url}")

                # Add CVE references from problems
                problems = issue.get("attributes", {}).get("problems", [])
                for problem in problems:
                    if problem.get("source") == "NVD" and problem.get("url"): # TODO - why only NVD
                        references += f"[{problem.get('id')}]({problem.get('url')})\n"

                # Extract CWE from classes
                cwe = None
                classes = issue.get("attributes", {}).get("classes", [])
                for cls in classes:
                    if cls.get("source") == "CWE" and cls.get("id", "").startswith("CWE-"):
                        try:
                            cwe = int(cls.get("id")[4:])
                            logger.debug(f"Extracted CWE number: {cwe}")
                            break
                        except ValueError:
                            logger.debug(f"Failed to parse CWE number from: {cls.get('id')}")

                # Get CVSS score from severities (prefer Snyk source)
                # TODO - need to work on that CVSS score
                cvss_score = None
                severities = issue.get("attributes", {}).get("severities", [])
                for severity_info in severities:
                    if severity_info.get("source") == "Snyk":
                        cvss_score = severity_info.get("score")
                        break
                if not cvss_score and severities:
                    cvss_score = severities[0].get("score")

                file_path = ""  # Not available for 3rd-party dependencies
                logger.debug(
                    f"Extracted metadata - CWE: {cwe}, CVSS: {cvss_score}, file_path: {file_path}")

                package_type = issue.get("attributes", {}).get("type", "package_vulnerability")
                # TODO - update schema or leave it
                # this is done so we would fit the length of field
                if package_type == "package_vulnerability":
                    package_type = "package"

                # Create or update Snyk issue tracking
                snyk_issue, created = Snyk_Issue.objects.update_or_create(
                    key=issue_id,
                    defaults={
                        "status": issue.get("attributes", {}).get("status", "open"),
                        "type": package_type,
                    },
                )
                logger.debug(
                    f"Snyk_Issue {'created' if created else 'updated'}: {snyk_issue.key}")

                # Only assign the Snyk_issue to the first finding related to the issue
                if Finding.objects.filter(snyk_issue=snyk_issue).exists():
                    logger.debug(
                        f"Snyk issue {issue_id} already has a finding, not assigning to new finding")
                    snyk_issue = None

                # Determine if finding is verified
                verified = severity in ["Critical", "High"]
                logger.debug(
                    f"Finding verification status: {verified} (based on severity: {severity})")

                find = Finding(
                    title=title,
                    cwe=cwe,
                    description=description,
                    test=test,
                    severity=severity,
                    references=references,
                    file_path=file_path,
                    verified=verified,
                    false_p=False,
                    duplicate=False,
                    out_of_scope=False,
                    mitigated=None,
                    mitigation="No mitigation provided",
                    impact="No impact provided",
                    static_finding=True,
                    snyk_issue=snyk_issue,
                    unique_id_from_tool=issue_id,
                    component_name=vuln_pkg,
                    component_version=vuln_version,
                )

                # Add CVSS score if available
                if cvss_score:
                    find.severity_justification = f"CVSS Score: {cvss_score}"
                    logger.debug(
                        f"Added CVSS score justification: {cvss_score}")

                items.append(find)
                logger.debug(f"Created finding for issue {issue_id}: {title}")

            logger.info(
                f"Successfully imported {len(items)} findings from {len(issues)} total issues")

        except Exception as e:
            logger.exception("Snyk API import issue")
            create_notification(
                event="snyk_failed",
                title="Snyk API import issue",
                description=str(e),
                icon="exclamation-triangle",
                source="Snyk API",
                obj=test.engagement.product,
            )

        return items

    @staticmethod
    def convert_snyk_severity(snyk_severity):
        """Convert Snyk severity to DefectDojo severity."""
        severity_map = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
        }
        converted = severity_map.get(snyk_severity.lower(), "Info")
        logger.debug(
            f"Converted Snyk severity '{snyk_severity}' to DefectDojo severity '{converted}'")
        return converted
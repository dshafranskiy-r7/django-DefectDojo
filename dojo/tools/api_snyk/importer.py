import logging
import textwrap
import json # for debugging

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
    def is_in_state(issue, state):
        """Check if the issue is <state> in Snyk."""
        status = issue.get("attributes", False).get("status", False)

        in_state = status == state

        if in_state:
            logger.debug(
                f"Issue {issue.get('id', 'unknown')} is {state} in Snyk")

        return in_state

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

            for issue in issues:
                issue_id = issue.get("id")
                logger.debug(f"Processing issue: {issue_id}")

                # Skip resolved issues ( we want to import ignored issues though )
                # TODO DIMI - test coverage
                if self.is_in_state(issue, "resolved"):
                    logger.debug(f"Skipping resolved issue: {issue_id}")
                    continue

                # TODO DIMI - test coverage
                issue_url = self.get_issue_url(client, org_id, issue)

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

                # Build description in Snyk parser format
                description_parts = []
                description_parts.append("## Component Details")
                if vuln_pkg:
                    description_parts.append(f"- **Vulnerable Package**: {vuln_pkg}")
                if vuln_version:
                    description_parts.append(f"- **Current Version**: {vuln_version}")
                
                # Add vulnerable path info if available from coordinates
                vulnerable_path = f"{vuln_pkg}@{vuln_version}" if vuln_pkg and vuln_version else "Unknown"
                description_parts.append(f"- **Vulnerable Path**: {vulnerable_path}")
                
                # Add main issue description
                description_parts.append("")  # Empty line
                description_parts.append(issue_title)
                
                # Add exploit details if available
                exploit_details = issue.get("attributes", {}).get("exploit_details", {})
                if exploit_details:
                    sources = exploit_details.get("sources", [])
                    if sources:
                        description_parts.append(f"\n**Exploit Sources**: {', '.join(sources)}")

                description = "\n".join(description_parts)
                logger.debug(
                    f"Built description with {len(description_parts)} parts")

                # Build references in Snyk parser format
                references = ""
                if issue_url:
                    references += f"**SNYK ID**: {issue_url}\n\n"
                    logger.debug(f"Added issue URL to references: {issue_url}")

                # Add CVE references from problems - include all sources, not just NVD
                problems = issue.get("attributes", {}).get("problems", [])
                cve_ids = []
                for problem in problems:
                    if problem.get("id") and problem.get("id").startswith("CVE-"):
                        cve_ids.append(problem.get("id"))
                    if problem.get("url"):
                        problem_title = problem.get("id", "Reference")
                        references += f"**{problem_title}**: {problem.get('url')}\n"
                
                # Add CWE references if multiple CWEs
                classes = issue.get("attributes", {}).get("classes", [])
                cwe_references = []
                for cls in classes:
                    if cls.get("source") == "CWE" and cls.get("id", "").startswith("CWE-"):
                        cwe_references.append(cls.get("id"))
                
                if len(cwe_references) > 1:
                    references += f"\nSeveral CWEs were reported: \n\n{', '.join(cwe_references)}\n"


                cwe = self.get_cwe_number(issue)

                cvss_score = self.get_cvss_score(issue)

                file_path = ""  # Not available for 3rd-party dependencies
                logger.debug(
                    f"Extracted metadata - CWE: {cwe}, CVSS: {cvss_score}, file_path: {file_path}")

                package_type = issue.get("attributes", {}).get("type", "package_vulnerability")

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

                find = Finding(
                    title=f"{vuln_pkg}: {issue_title}" if vuln_pkg else issue_title,
                    cwe=cwe,
                    description=description,
                    test=test,
                    severity=severity,
                    severity_justification=f"Issue severity of: **{severity}** from a base CVSS score of: **{cvss_score}**" if cvss_score else f"Issue severity of: **{severity}**",
                    references=references,
                    file_path=f"{vuln_pkg}@{vuln_version}" if vuln_pkg and vuln_version else "",
                    verified=severity in ["Critical", "High"],
                    false_p=False,
                    duplicate=False,
                    out_of_scope=False,
                    mitigated=None,
                    mitigation="A fix (if available) will be provided in the description.",
                    impact=severity,  # Set impact to severity like parser.py
                    static_finding=True,
                    dynamic_finding=False,  # Add missing field from parser.py
                    snyk_issue=snyk_issue,
                    vuln_id_from_tool=issue_id,  # Use vuln_id_from_tool like parser.py
                    component_name=vuln_pkg,
                    component_version=vuln_version,
                )

                # Add CVSS vector if available (like parser.py)
                severities = issue.get("attributes", {}).get("severities", [])
                for severity_info in severities:
                    if severity_info.get("source") == "Snyk" and severity_info.get("vector"):
                        try:
                            from cvss.cvss3 import CVSS3
                            find.cvssv3 = CVSS3(severity_info["vector"]).clean_vector()
                            logger.debug(f"Added CVSS vector: {find.cvssv3}")
                            break
                        except ImportError:
                            logger.warning("cvss library not available for CVSS vector processing")
                        except Exception as e:
                            logger.warning(f"Failed to process CVSS vector: {e}")

                # Add EPSS scores if available (like parser.py)
                # Note: EPSS data is typically not available in Snyk API v1, but we check anyway
                risk_data = issue.get("attributes", {}).get("risk", {})
                if risk_data and "epss" in risk_data:
                    epss_data = risk_data["epss"]
                    if "probability" in epss_data:
                        find.epss_score = epss_data["probability"]
                        logger.debug(f"Added EPSS score: {find.epss_score}")
                    if "percentile" in epss_data:
                        find.epss_percentile = epss_data["percentile"]
                        logger.debug(f"Added EPSS percentile: {find.epss_percentile}")

                # Add vulnerability IDs like parser.py
                find.unsaved_vulnerability_ids = cve_ids if cve_ids else []
                if cve_ids:
                    logger.debug(f"Added vulnerability IDs: {cve_ids}")

                # Add tags for additional metadata (like parser.py)
                find.unsaved_tags = []
                if package_type:
                    find.unsaved_tags.append(f"snyk_type:{package_type}")

                # Add CVSS score if available (legacy support)
                if cvss_score:
                    logger.debug(f"Added CVSS score justification: {cvss_score}")

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


    def get_issue_url(self, client, org_id, issue):
        key = issue["attributes"]["key"]
        project = issue["relationships"]["scan_item"]["data"]["id"]
        org_name = client.get_id_to_org_mapping().get(org_id, "unknown_org")

        # TODO - this one is different from default one
        issue_url = f"https://app.snyk.io/org/{org_name}/project/{project}#issue-{key}"
        return issue_url

    # TODO DIMI - test coverage
    @staticmethod
    def get_cwe_number(issue):
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
        return cwe

    # TODO DIMI - test coverage
    @staticmethod
    def get_cvss_score(issue):
        cvss_score = None
        severities = issue.get("attributes", {}).get("severities", [])
        for severity_info in severities:
            if severity_info.get("source") == "Snyk":
                cvss_score = severity_info.get("score")
                break
        if not cvss_score and severities:
            cvss_score = severities[0].get("score")
        return cvss_score

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
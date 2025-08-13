import logging
import re
import textwrap

import html2text
from django.conf import settings
from django.core.exceptions import ValidationError

from dojo.models import Finding
from dojo.notifications.helper import create_notification

from .api_client import SnykAPI

logger = logging.getLogger(__name__)


class SnykApiImporter:

    """
    This class imports from Snyk all open issues related to the project as findings.
    """

    def get_findings(self, filename, test):
        return self.import_issues(test)

    @staticmethod
    def is_open(status):
        """Check if a Snyk issue is open."""
        return status.lower() in {"open"}

    @staticmethod
    def is_ignored(issue):
        """Check if a Snyk issue is ignored."""
        return issue.get("attributes", {}).get("ignored", False)

    @staticmethod
    def prepare_client(test):
        product = test.engagement.product
        if test.api_scan_configuration:
            config = test.api_scan_configuration
            # Double check of config
            if config.product != product:
                msg = (
                    "Product API Scan Configuration and Product do not match. "
                    f'Product: "{product.name}" ({product.id}), config.product: "{config.product.name}" ({config.product.id})'
                )
                raise ValidationError(msg)
        else:
            snyk_configs = product.product_api_scan_configuration_set.filter(
                product=product,
                tool_configuration__tool_type__name="Snyk",
            )
            if snyk_configs.count() == 1:
                config = snyk_configs.first()
            elif snyk_configs.count() > 1:
                msg = (
                    "More than one Product API Scan Configuration has been configured, but none of them has been "
                    "chosen. Please specify which one should be used. "
                    f'Product: "{product.name}" ({product.id})'
                )
                raise ValidationError(msg)
            else:
                msg = (
                    "There are no API Scan Configurations for this Product.\n"
                    "Please add at least one API Scan Configuration for Snyk to this Product. "
                    f'Product: "{product.name}" ({product.id})'
                )
                raise ValidationError(msg)

        return SnykAPI(tool_config=config.tool_configuration), config

    def import_issues(self, test):
        items = []

        try:
            client, config = self.prepare_client(test)
            # Get the organization ID from service key 2
            organization = (
                config.service_key_2
                if (config and config.service_key_2)
                else None
            )
            # Get the project ID from service key 1
            if config and config.service_key_1:
                project_id = config.service_key_1
                project = client.get_project(project_id, organization=organization)
            else:
                # Try to find project by name
                project = client.find_project(
                    test.engagement.product.name,
                    organization=organization,
                )
                project_id = project.get("id")

            # Get issues from Snyk
            issues = client.find_issues(project_id, organization=organization)
            
            logger.info(
                f'Found {len(issues)} issues for project {project_id}',
            )

            for issue in issues:
                attributes = issue.get("attributes", {})
                status = attributes.get("status", "")
                
                # Skip ignored or resolved issues
                if not self.is_open(status) or self.is_ignored(issue):
                    continue

                issue_type = attributes.get("type", "")
                title = attributes.get("title", "")
                description = attributes.get("description", "")
                
                # Limit title length
                if len(title) > 511:
                    title = title[:507] + "..."

                # Get severity information
                severities = attributes.get("severities", [])
                severity = "Info"
                cvss_vector = None
                cvss_score = None
                
                if severities:
                    primary_severity = next(
                        (s for s in severities if s.get("type") == "primary"), 
                        severities[0]
                    )
                    severity = self.convert_snyk_severity(primary_severity.get("level", "info"))
                    cvss_vector = primary_severity.get("vector")
                    cvss_score = primary_severity.get("score")

                # Get CWE information from classes
                cwe = None
                classes = attributes.get("classes", [])
                for cls in classes:
                    if cls.get("source") == "CWE" and cls.get("type") == "weakness":
                        cwe_match = re.search(r"CWE-(\d+)", cls.get("id", ""))
                        if cwe_match:
                            cwe = int(cwe_match.group(1))
                            break

                # Get file path and line information from coordinates
                file_path = None
                line = None
                coordinates = attributes.get("coordinates", [])
                if coordinates:
                    representations = coordinates[0].get("representations", [])
                    if representations:
                        file_path = representations[0].get("resourcePath")

                # Create Snyk permalink
                snyk_permalink = f"[Issue permalink](https://app.snyk.io/org/{organization}/project/{project_id}/issue/{issue.get('id')}) \n"
                references = snyk_permalink

                # Get additional references
                if "slots" in attributes and "references" in attributes["slots"]:
                    for ref in attributes["slots"]["references"]:
                        ref_title = ref.get("title", "Reference")
                        ref_url = ref.get("url", "")
                        if ref_url:
                            references += f"[{ref_title}]({ref_url})\n"

                find = Finding(
                    title=title,
                    cwe=cwe,
                    description=description,
                    test=test,
                    severity=severity,
                    references=references,
                    file_path=file_path,
                    line=line,
                    verified=True,  # Snyk issues are considered verified
                    false_p=False,
                    duplicate=False,
                    out_of_scope=False,
                    mitigated=None,
                    mitigation="No mitigation provided",
                    impact="No impact provided",
                    static_finding=True,
                    unique_id_from_tool=issue.get("id"),
                )
                
                # Add CVSS information if available
                if cvss_vector:
                    find.cvssv3 = cvss_vector
                if cvss_score:
                    find.cvssv3_score = cvss_score
                
                items.append(find)

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
        """Convert Snyk severity levels to DefectDojo severity levels."""
        sev = snyk_severity.lower()
        if sev == "critical":
            return "Critical"
        if sev == "high":
            return "High"
        if sev == "medium":
            return "Medium"
        if sev == "low":
            return "Low"
        return "Info"

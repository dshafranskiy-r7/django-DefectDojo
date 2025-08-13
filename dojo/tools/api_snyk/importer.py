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
        return issue.get("ignored", False)

    @staticmethod
    def is_patched(issue):
        """Check if the issue is patched."""
        return issue.get("patched", False)

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
            
            # Get organization ID from service key 1
            org_id = config.service_key_1
            # Get project ID from service key 2 (optional)
            project_id = config.service_key_2 if config.service_key_2 else None
            
            # Get issues from Snyk
            issues = client.get_issues(org_id, project_id)
            logger.info(
                f"Found {len(issues)} issues for {'project ' + project_id if project_id else 'organization ' + org_id}",
            )

            for issue in issues:
                # Skip ignored issues
                if self.is_ignored(issue):
                    continue

                issue_id = issue.get("id")
                issue_url = issue.get("url", "")
                
                # Get detailed issue information
                issue_title = issue.get("title", "Unknown Snyk Issue")
                title = textwrap.shorten(text=issue_title, width=500)
                
                # Extract vulnerability information
                vuln_pkg = issue.get("package", "")
                vuln_version = issue.get("version", "")
                severity = self.convert_snyk_severity(issue.get("severity", "low"))
                
                # Build description
                description_parts = []
                if issue.get("description"):
                    description_parts.append(issue.get("description"))
                
                if vuln_pkg:
                    description_parts.append(f"Package: {vuln_pkg}")
                
                if vuln_version:
                    description_parts.append(f"Version: {vuln_version}")
                
                description = "\n\n".join(description_parts) if description_parts else "No description available"
                
                # Build references
                references = ""
                if issue_url:
                    references += f"[Snyk Issue]({issue_url})\n"
                
                # Extract additional details
                cwe = self.extract_cwe(issue)
                cvss_score = issue.get("cvssScore")
                file_path = issue.get("from", [""])[0] if issue.get("from") else ""
                
                # Create or update Snyk issue tracking
                snyk_issue, _ = Snyk_Issue.objects.update_or_create(
                    key=issue_id,
                    defaults={
                        "status": "open" if not self.is_ignored(issue) else "ignored",
                        "type": issue.get("type", "vuln"),
                    },
                )

                # Only assign the Snyk_issue to the first finding related to the issue
                if Finding.objects.filter(snyk_issue=snyk_issue).exists():
                    snyk_issue = None

                # Determine if finding is verified
                verified = severity in ["Critical", "High"]
                
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
        """Convert Snyk severity to DefectDojo severity."""
        severity_map = {
            "critical": "Critical",
            "high": "High", 
            "medium": "Medium",
            "low": "Low",
        }
        return severity_map.get(snyk_severity.lower(), "Info")

    @staticmethod
    def extract_cwe(issue):
        """Extract CWE number from Snyk issue."""
        # Try to find CWE in various fields
        for field in ["cwe", "identifiers"]:
            if field in issue:
                cwe_data = issue[field]
                if isinstance(cwe_data, list):
                    for item in cwe_data:
                        if isinstance(item, str) and item.startswith("CWE-"):
                            try:
                                return int(item[4:])
                            except ValueError:
                                continue
                        elif isinstance(item, dict) and item.get("type") == "CWE":
                            try:
                                return int(item.get("value", "").replace("CWE-", ""))
                            except ValueError:
                                continue
                elif isinstance(cwe_data, str) and cwe_data.startswith("CWE-"):
                    try:
                        return int(cwe_data[4:])
                    except ValueError:
                        continue
        return None
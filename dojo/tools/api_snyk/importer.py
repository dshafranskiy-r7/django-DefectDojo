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
        ignored = issue.get("ignored", False)
        if ignored:
            logger.debug(f"Issue {issue.get('id', 'unknown')} is ignored in Snyk")
        return ignored

    @staticmethod
    def is_patched(issue):
        """Check if the issue is patched."""
        patched = issue.get("patched", False)
        if patched:
            logger.debug(f"Issue {issue.get('id', 'unknown')} is patched in Snyk")
        return patched

    @staticmethod
    def prepare_client(test):
        product = test.engagement.product
        logger.debug(f"Preparing Snyk client for test {test.id} in product '{product.name}' ({product.id})")
        
        if test.api_scan_configuration:
            config = test.api_scan_configuration
            logger.debug(f"Using test-specific API scan configuration: {config.id}")
            # Double check of config
            if config.product != product:
                msg = (
                    "Product API Scan Configuration and Product do not match. "
                    f'Product: "{product.name}" ({product.id}), config.product: "{config.product.name}" ({config.product.id})'
                )
                logger.error(msg)
                raise ValidationError(msg)
        else:
            logger.debug("No test-specific configuration, searching for product configurations")
            snyk_configs = product.product_api_scan_configuration_set.filter(
                product=product,
                tool_configuration__tool_type__name="Snyk",
            )
            logger.debug(f"Found {snyk_configs.count()} Snyk configurations for product")
            
            if snyk_configs.count() == 1:
                config = snyk_configs.first()
                logger.debug(f"Using single product API scan configuration: {config.id}")
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

        logger.debug(f"Successfully prepared Snyk client with configuration {config.id}")
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
            
            logger.debug(f"Import configuration - org_id: {org_id}, project_id: {project_id}")
            
            # Get issues from Snyk
            issues = client.get_issues(org_id, project_id)
            logger.info(
                f"Found {len(issues)} issues for {'project ' + project_id if project_id else 'organization ' + org_id}",
            )

            for issue in issues:
                issue_id = issue.get("id")
                logger.debug(f"Processing issue: {issue_id}")
                
                # Skip ignored issues
                if self.is_ignored(issue):
                    logger.debug(f"Skipping ignored issue: {issue_id}")
                    continue

                issue_url = issue.get("url", "")
                
                # Get detailed issue information
                issue_title = issue.get("title", "Unknown Snyk Issue")
                title = textwrap.shorten(text=issue_title, width=500)
                logger.debug(f"Issue title: {title}")
                
                # Extract vulnerability information
                vuln_pkg = issue.get("package", "")
                vuln_version = issue.get("version", "")
                snyk_severity = issue.get("severity", "low")
                severity = self.convert_snyk_severity(snyk_severity)
                logger.debug(f"Issue details - package: {vuln_pkg}, version: {vuln_version}, severity: {snyk_severity} -> {severity}")
                
                # Build description
                description_parts = []
                if issue.get("description"):
                    description_parts.append(issue.get("description"))
                
                if vuln_pkg:
                    description_parts.append(f"Package: {vuln_pkg}")
                
                if vuln_version:
                    description_parts.append(f"Version: {vuln_version}")
                
                description = "\n\n".join(description_parts) if description_parts else "No description available"
                logger.debug(f"Built description with {len(description_parts)} parts")
                
                # Build references
                references = ""
                if issue_url:
                    references += f"[Snyk Issue]({issue_url})\n"
                    logger.debug(f"Added issue URL to references: {issue_url}")
                
                # Extract additional details
                cwe = self.extract_cwe(issue)
                cvss_score = issue.get("cvssScore")
                file_path = issue.get("from", [""])[0] if issue.get("from") else ""
                logger.debug(f"Extracted metadata - CWE: {cwe}, CVSS: {cvss_score}, file_path: {file_path}")
                
                # Create or update Snyk issue tracking
                snyk_issue, created = Snyk_Issue.objects.update_or_create(
                    key=issue_id,
                    defaults={
                        "status": "open" if not self.is_ignored(issue) else "ignored",
                        "type": issue.get("type", "vuln"),
                    },
                )
                logger.debug(f"Snyk_Issue {'created' if created else 'updated'}: {snyk_issue.key}")

                # Only assign the Snyk_issue to the first finding related to the issue
                if Finding.objects.filter(snyk_issue=snyk_issue).exists():
                    logger.debug(f"Snyk issue {issue_id} already has a finding, not assigning to new finding")
                    snyk_issue = None

                # Determine if finding is verified
                verified = severity in ["Critical", "High"]
                logger.debug(f"Finding verification status: {verified} (based on severity: {severity})")
                
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
                    logger.debug(f"Added CVSS score justification: {cvss_score}")
                
                items.append(find)
                logger.debug(f"Created finding for issue {issue_id}: {title}")

            logger.info(f"Successfully imported {len(items)} findings from {len(issues)} total issues")

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
        logger.debug(f"Converted Snyk severity '{snyk_severity}' to DefectDojo severity '{converted}'")
        return converted

    @staticmethod
    def extract_cwe(issue):
        """Extract CWE number from Snyk issue."""
        logger.debug(f"Extracting CWE from issue {issue.get('id', 'unknown')}")
        
        # Try to find CWE in various fields
        for field in ["cwe", "identifiers"]:
            if field in issue:
                cwe_data = issue[field]
                logger.debug(f"Found CWE data in field '{field}': {cwe_data}")
                
                if isinstance(cwe_data, list):
                    for item in cwe_data:
                        if isinstance(item, str) and item.startswith("CWE-"):
                            try:
                                cwe_num = int(item[4:])
                                logger.debug(f"Extracted CWE number: {cwe_num}")
                                return cwe_num
                            except ValueError:
                                logger.debug(f"Failed to parse CWE number from: {item}")
                                continue
                        elif isinstance(item, dict) and item.get("type") == "CWE":
                            try:
                                cwe_num = int(item.get("value", "").replace("CWE-", ""))
                                logger.debug(f"Extracted CWE number from dict: {cwe_num}")
                                return cwe_num
                            except ValueError:
                                logger.debug(f"Failed to parse CWE number from dict: {item}")
                                continue
                elif isinstance(cwe_data, str) and cwe_data.startswith("CWE-"):
                    try:
                        cwe_num = int(cwe_data[4:])
                        logger.debug(f"Extracted CWE number from string: {cwe_num}")
                        return cwe_num
                    except ValueError:
                        logger.debug(f"Failed to parse CWE number from string: {cwe_data}")
                        continue
        
        logger.debug("No CWE found in issue")
        return None
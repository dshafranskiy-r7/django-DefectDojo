import logging
import requests
from django.conf import settings
from requests.exceptions import JSONDecodeError as RequestsJSONDecodeError

from dojo.tools.appcheck_web_application_scanner.engines import base
from dojo.utils import prepare_for_view

logger = logging.getLogger(__name__)

# TODO - move to API config params
snyk_api_version="2024-10-15"

class SnykAPI:
    def __init__(self, tool_config):
        logger.debug(f"Initializing Snyk API client with URL: {tool_config.url}")
        self.session = requests.Session()
        self.default_headers = {
            "User-Agent": "DefectDojo",
            "authorization": tool_config.api_key,
            "accept": "application/vnd.api+json"
        }
        self.snyk_api_url = tool_config.url.rstrip("/")
        # not sure if this is necessary though
        if not self.snyk_api_url.endswith("/rest"):
            self.snyk_api_url += "/rest"

        logger.debug(f"Snyk API URL configured as: {self.snyk_api_url}")

    # TODO - this might only run once
    def get_id_to_org_mapping(self):
        url = f"/orgs?version={snyk_api_version}"
        response = requests.get(self.snyk_api_url + url, headers=self.default_headers)
        response.raise_for_status()

        return {item["id"]: item["attributes"]["slug"] for item in response.json()["data"]}

    def get_organizations(self):
        """
        Get list of organizations the user has access to.
        """
        logger.debug("Fetching organizations from Snyk API")
        response = self.session.get(
            url=f"{self.snyk_api_url}/orgs",
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            logger.error(f"Failed to get organizations: {response.status_code} - {response.content.decode('utf-8')}")
            msg = (
                f"Unable to get organizations "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        orgs_data = response.json().get("orgs", [])
        logger.info(f"Retrieved {len(orgs_data)} organizations from Snyk")
        logger.debug(f"Organizations: {[org.get('name', org.get('id', 'unknown')) for org in orgs_data]}")
        return orgs_data

    def get_organization(self, org_id):
        """
        Get details of a specific organization.
        """
        logger.debug(f"Fetching organization details for ID: {org_id}")
        response = self.session.get(
            url=f"{self.snyk_api_url}/orgs/{org_id}?version={snyk_api_version}",
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            logger.error(f"Failed to get organization {org_id}: {response.status_code} - {response.content.decode('utf-8')}")
            msg = (
                f"Unable to get organization {org_id} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        org_name = response.json().get("data", {}).get("attributes", {}).get("slug", "unknown-organization")

        logger.debug(f"Retrieved organization: {org_name} from ID: {org_id}")
        return org_name

    def get_projects(self, org_id):
        """
        Get all projects for an organization.
        """
        logger.debug(f"Fetching projects for organization: {org_id}")

        response = self.session.get(
            url=f"{self.snyk_api_url}/orgs/{org_id}/projects?version={snyk_api_version}&meta_count=only",
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            logger.error(f"Failed to get projects for organization {org_id}: {response.status_code} - {response.content.decode('utf-8')}")
            msg = (
                f"Unable to get projects for organization {org_id} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        projects_data = response.json().get("meta", []).get("count", 0)
        logger.info(f"Retrieved {projects_data} projects for organization {org_id}")
        return projects_data

    def get_project(self, org_id, project_id):
        """
        Get details of a specific project.
        """
        logger.debug(f"Fetching project details for ID: {project_id} in organization: {org_id}")
        response = self.session.get(
            url=f"{self.snyk_api_url}/org/{org_id}/project/{project_id}",
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            logger.error(f"Failed to get project {project_id}: {response.status_code} - {response.content.decode('utf-8')}")
            msg = (
                f"Unable to get project {project_id} in organization {org_id} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        project_data = response.json()
        logger.debug(f"Retrieved project: {project_data.get('name', project_id) if project_data else 'None'}")
        return project_data

    def get_issues(self, org_id, project_id=None):
        """
        Get issues for an organization or specific project.
        """
        url = f"{self.snyk_api_url}/orgs/{org_id}/issues?version={snyk_api_version}"
        logger.debug(f"Fetching issues for organization {org_id}")

        response = self.session.get(
            url=url,
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            logger.error(f"Failed to get issues: {response.status_code} - {response.content.decode('utf-8')}")
            msg = (
                f"Unable to get issues for {'project ' + project_id if project_id else 'organization'} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        issues_data = response.json().get("data", [])
        scope = f"project {project_id}" if project_id else f"organization {org_id}"
        logger.info(f"Retrieved {len(issues_data)} issues for {scope}")
        logger.debug(f"Issue types: {list(set(issue.get('type', 'unknown') for issue in issues_data))}")
        return issues_data

    def get_issue(self, org_id, issue_id):
        """
        Get details of a specific issue.
        """
        logger.debug(f"Fetching issue details for ID: {issue_id} in organization: {org_id}")
        response = self.session.get(
            url=f"{self.snyk_api_url}/org/{org_id}/issue/{issue_id}",
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            logger.error(f"Failed to get issue {issue_id}: {response.status_code} - {response.content.decode('utf-8')}")
            msg = (
                f"Unable to get issue {issue_id} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        issue_data = response.json().get("issue")
        logger.debug(f"Retrieved issue: {issue_data.get('title', issue_id) if issue_data else 'None'}")
        return issue_data

    def ignore_issue(self, org_id, issue_id, reason="false-positive", notes=""):
        """
        Ignore an issue (mark as false positive or won't fix).
        """
        logger.debug(f"Ignoring issue {issue_id} with reason: {reason}")
        data = {
            "ignorePath": "*",
            "reason": reason,
            "reasonType": "not-vulnerable" if reason == "false-positive" else "wont-fix",
        }
        if notes:
            data["disregardIfFixable"] = False
            data["notes"] = notes
            logger.debug(f"Adding notes to ignore action: {notes}")

        response = self.session.post(
            url=f"{self.snyk_api_url}/org/{org_id}/project/{issue_id}/ignore/*",
            headers=self.default_headers,
            json=data,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            logger.error(f"Failed to ignore issue {issue_id}: {response.status_code} - {response.content.decode('utf-8')}")
            msg = (
                f"Unable to ignore issue {issue_id} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        logger.info(f"Successfully ignored issue {issue_id} with reason: {reason}")

    def unignore_issue(self, org_id, issue_id):
        """
        Unignore an issue.
        """
        logger.debug(f"Unignoring issue {issue_id}")
        response = self.session.delete(
            url=f"{self.snyk_api_url}/org/{org_id}/project/{issue_id}/ignore/*",
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            logger.error(f"Failed to unignore issue {issue_id}: {response.status_code} - {response.content.decode('utf-8')}")
            msg = (
                f"Unable to unignore issue {issue_id} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        logger.info(f"Successfully unignored issue {issue_id}")

    def test_connection(self):
        """Returns user information or raise error."""
        logger.debug("Testing Snyk API connection")
        response = self.session.get(
            url=f"{self.snyk_api_url}/self?version={snyk_api_version}",
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            logger.error(f"Connection test failed: {response.status_code} - {response.content.decode('utf-8')}")
            msg = (
                f"Unable to connect to Snyk "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        try:
            user_data = response.json()
            username = user_data["data"]["attributes"]["name"]
            logger.info(f"Successfully connected to Snyk as user: {username}")
        except RequestsJSONDecodeError:
            logger.error("Connection test received non-JSON response")
            msg = (
                f""" Test request was successful (there was no HTTP-4xx or HTTP-5xx) but response doesn't contain
                expected JSON response. Snyk responded with HTTP-{response.status_code} ({response.reason}).
                This is full response: {response.text}
                """
            )
            raise Exception(msg)
        return f"Successfully connected to Snyk as user: {username}"

    def test_product_connection(self, api_scan_configuration):
        org_id = api_scan_configuration.service_key_1
        project_id = api_scan_configuration.service_key_2 or None

        logger.debug(f"Testing product connection for org_id: {org_id}, project_id: {project_id}")

        org_name = self.get_organization(org_id)

        logger.debug(f"Successfully accessed organization: {org_name}")

        projects_count = self.get_projects(org_id)
        logger.info(f"Product connection test successful for organization '{org_name}' with {projects_count} projects")
        return f"Successfully connected to Snyk organization '{org_name}' with {projects_count} projects"
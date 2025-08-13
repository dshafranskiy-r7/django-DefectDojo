import requests
from django.conf import settings
from requests.exceptions import JSONDecodeError as RequestsJSONDecodeError

from dojo.utils import prepare_for_view


class SnykAPI:
    def __init__(self, tool_config):
        self.session = requests.Session()
        self.default_headers = {
            "User-Agent": "DefectDojo",
            "Authorization": f"token {prepare_for_view(tool_config.api_key)}",
            "Content-Type": "application/vnd.api+json"
        }
        self.snyk_api_url = tool_config.url.rstrip("/")
        if not self.snyk_api_url.endswith("/api/v1"):
            self.snyk_api_url += "/api/v1"

    def get_organizations(self):
        """
        Get list of organizations the user has access to.
        """
        response = self.session.get(
            url=f"{self.snyk_api_url}/orgs",
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            msg = (
                f"Unable to get organizations "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        return response.json().get("orgs", [])

    def get_organization(self, org_id):
        """
        Get details of a specific organization.
        """
        response = self.session.get(
            url=f"{self.snyk_api_url}/org/{org_id}",
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            msg = (
                f"Unable to get organization {org_id} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        return response.json().get("org")

    def get_projects(self, org_id):
        """
        Get all projects for an organization.
        """
        response = self.session.post(
            url=f"{self.snyk_api_url}/org/{org_id}/projects",
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            msg = (
                f"Unable to get projects for organization {org_id} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        return response.json().get("projects", [])

    def get_project(self, org_id, project_id):
        """
        Get details of a specific project.
        """
        response = self.session.get(
            url=f"{self.snyk_api_url}/org/{org_id}/project/{project_id}",
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            msg = (
                f"Unable to get project {project_id} in organization {org_id} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        return response.json()

    def get_issues(self, org_id, project_id=None):
        """
        Get issues for an organization or specific project.
        """
        if project_id:
            url = f"{self.snyk_api_url}/org/{org_id}/project/{project_id}/issues"
        else:
            url = f"{self.snyk_api_url}/org/{org_id}/issues"
        
        response = self.session.post(
            url=url,
            headers=self.default_headers,
            json={"filters": {}},
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            msg = (
                f"Unable to get issues for {'project ' + project_id if project_id else 'organization'} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        return response.json().get("issues", [])

    def get_issue(self, org_id, issue_id):
        """
        Get details of a specific issue.
        """
        response = self.session.get(
            url=f"{self.snyk_api_url}/org/{org_id}/issue/{issue_id}",
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            msg = (
                f"Unable to get issue {issue_id} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        return response.json().get("issue")

    def ignore_issue(self, org_id, issue_id, reason="false-positive", notes=""):
        """
        Ignore an issue (mark as false positive or won't fix).
        """
        data = {
            "ignorePath": "*",
            "reason": reason,
            "reasonType": "not-vulnerable" if reason == "false-positive" else "wont-fix",
        }
        if notes:
            data["disregardIfFixable"] = False
            data["notes"] = notes

        response = self.session.post(
            url=f"{self.snyk_api_url}/org/{org_id}/project/{issue_id}/ignore/*",
            headers=self.default_headers,
            json=data,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            msg = (
                f"Unable to ignore issue {issue_id} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

    def unignore_issue(self, org_id, issue_id):
        """
        Unignore an issue.
        """
        response = self.session.delete(
            url=f"{self.snyk_api_url}/org/{org_id}/project/{issue_id}/ignore/*",
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            msg = (
                f"Unable to unignore issue {issue_id} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

    def test_connection(self):
        """Returns user information or raise error."""
        response = self.session.get(
            url=f"{self.snyk_api_url}/user/me",
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            msg = (
                f"Unable to connect to Snyk "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        try:
            user_data = response.json()
            username = user_data.get("username", "unknown")
        except RequestsJSONDecodeError:
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
        
        # Test organization access
        org = self.get_organization(org_id)
        org_name = org.get("name", org_id)
        
        if project_id:
            # Test project access
            project = self.get_project(org_id, project_id)
            project_name = project.get("name", project_id)
            return f"Successfully connected to Snyk project '{project_name}' in organization '{org_name}'"
        else:
            # Just test organization access
            projects = self.get_projects(org_id)
            return f"Successfully connected to Snyk organization '{org_name}' with {len(projects)} projects"
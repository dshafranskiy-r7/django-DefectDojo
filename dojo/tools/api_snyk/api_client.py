import requests
from django.conf import settings
from requests.exceptions import JSONDecodeError as RequestsJSONDecodeError

from dojo.utils import prepare_for_view


class SnykAPI:
    def __init__(self, tool_config):
        # API version for Snyk REST API
        self.api_version = "2024-06-10"
        
        # Organization ID for Snyk API
        self.org_id = None
        
        # Parse the extras field to extract organization ID
        if tool_config.extras and "OrgID" in tool_config.extras:
            self.org_id = tool_config.extras.replace("OrgID=", "")

        self.session = requests.Session()
        self.default_headers = {
            "User-Agent": "DefectDojo",
            "Content-Type": "application/vnd.api+json",
        }
        
        # Set API base URL
        self.snyk_api_url = "https://api.snyk.io/rest"
        
        # Handle authentication
        if tool_config.authentication_type == "API":
            self.session.headers.update({
                "Authorization": f"token {tool_config.api_key}"
            })
        else:
            msg = f"Snyk Authentication type {tool_config.authentication_type} not supported. Only API key authentication is supported."
            raise Exception(msg)

    def find_project(self, project_name, organization=None):
        """
        Search for projects by name in the organization.
        :param project_name: Name of the project to search for
        :param organization: Organization ID (optional, uses self.org_id if not provided)
        :return: Project data from Snyk API
        """
        org_id = organization or self.org_id
        if not org_id:
            raise Exception("Organization ID is required to search for projects")

        parameters = {
            "version": self.api_version,
            "names": [project_name],
            "limit": 100
        }

        response = self.session.get(
            url=f"{self.snyk_api_url}/orgs/{org_id}/projects",
            params=parameters,
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            msg = (
                f"Unable to find the project {project_name} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        projects = response.json().get("data", [])
        for project in projects:
            if project.get("attributes", {}).get("name") == project_name:
                return project
        
        msg = f"Project '{project_name}' not found in organization {org_id}"
        raise Exception(msg)

    def get_project(self, project_id, organization=None):
        """
        Returns a project by ID.
        :param project_id: The Snyk project ID
        :param organization: Organization ID (optional, uses self.org_id if not provided)
        :return: Project data from Snyk API
        """
        org_id = organization or self.org_id
        if not org_id:
            raise Exception("Organization ID is required to get project")

        parameters = {
            "version": self.api_version
        }

        response = self.session.get(
            url=f"{self.snyk_api_url}/orgs/{org_id}/projects/{project_id}",
            params=parameters,
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            msg = (
                f"Unable to find the project {project_id} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        return response.json().get("data")

    def find_issues(self, project_id, organization=None, issue_types=None):
        """
        Search for issues in a project.
        :param project_id: Snyk project ID
        :param organization: Organization ID (optional, uses self.org_id if not provided)
        :param issue_types: List of issue types to filter (optional)
        :return: List of issues from Snyk API
        """
        org_id = organization or self.org_id
        if not org_id:
            raise Exception("Organization ID is required to find issues")

        # Use pagination to get all issues
        page_limit = 100
        starting_after = None
        all_issues = []

        while True:
            parameters = {
                "version": self.api_version,
                "scan_item.id": project_id,
                "scan_item.type": "project",
                "limit": page_limit
            }

            if starting_after:
                parameters["starting_after"] = starting_after

            if issue_types:
                parameters["type"] = issue_types

            response = self.session.get(
                url=f"{self.snyk_api_url}/orgs/{org_id}/issues",
                params=parameters,
                headers=self.default_headers,
                timeout=settings.REQUESTS_TIMEOUT,
            )

            if not response.ok:
                msg = (
                    f"Unable to find issues for project {project_id} "
                    f'due to {response.status_code} - {response.content.decode("utf-8")}'
                )
                raise Exception(msg)

            response_data = response.json()
            issues_page = response_data.get("data", [])
            
            if not issues_page:
                break
                
            all_issues.extend(issues_page)
            
            # Check if there are more pages
            links = response_data.get("links", {})
            if "next" not in links:
                break
                
            # Extract starting_after from next URL or use the last item ID
            if issues_page:
                starting_after = f"v1.{issues_page[-1]['id']}"

        return all_issues

    def get_issue(self, issue_id, organization=None):
        """
        Get a specific issue by ID.
        :param issue_id: The Snyk issue ID
        :param organization: Organization ID (optional, uses self.org_id if not provided)
        :return: Issue data from Snyk API
        """
        org_id = organization or self.org_id
        if not org_id:
            raise Exception("Organization ID is required to get issue")

        parameters = {
            "version": self.api_version
        }

        response = self.session.get(
            url=f"{self.snyk_api_url}/orgs/{org_id}/issues/{issue_id}",
            params=parameters,
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            msg = (
                f"Unable to get issue {issue_id} "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        return response.json().get("data")

    def test_connection(self):
        """Returns number of organizations or raise error."""
        parameters = {
            "version": self.api_version
        }

        # Test connection by getting user info
        response = self.session.get(
            url=f"{self.snyk_api_url}/self",
            params=parameters,
            headers=self.default_headers,
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if not response.ok:
            msg = (
                f"Unable to connect to Snyk API "
                f'due to {response.status_code} - {response.content.decode("utf-8")}'
            )
            raise Exception(msg)

        try:
            user_data = response.json()
            user_id = user_data.get("data", {}).get("id", "unknown")
        except RequestsJSONDecodeError:
            msg = (
                f"Test request was successful (there was no HTTP-4xx or HTTP-5xx) but response doesn't contain "
                f"expected JSON response. Snyk responded with HTTP-{response.status_code} ({response.reason}). "
                f"This is full response: {response.text}"
            )
            raise Exception(msg)
        
        return f"Successfully connected to Snyk API as user {user_id}"

    def test_product_connection(self, api_scan_configuration):
        """Test connection to a specific project/organization."""
        organization = api_scan_configuration.service_key_2 or self.org_id
        project_id = api_scan_configuration.service_key_1
        
        if not organization:
            raise Exception("Organization ID is required for Snyk API")
            
        if not project_id:
            raise Exception("Project ID is required for Snyk API")
        
        project = self.get_project(project_id, organization=organization)
        project_name = project.get("attributes", {}).get("name", "Unknown")
        
        return f"You have access to project '{project_name}' in organization {organization}"

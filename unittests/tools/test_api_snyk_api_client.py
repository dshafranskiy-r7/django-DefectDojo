import json
from unittest import mock
from unittest.mock import Mock, patch

import requests
from django.test import TestCase

from dojo.models import (
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Tool_Configuration,
    Tool_Type,
)
from dojo.tools.api_snyk.api_client import SnykAPI, IGNORE_REASON
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestSnykAPIClient(DojoTestCase):
    def setUp(self):
        product_type, _ = Product_Type.objects.get_or_create(name="Fake unit tests")
        product, _ = Product.objects.get_or_create(name="product", prod_type=product_type)
        # build Snyk conf
        tool_type, _ = Tool_Type.objects.get_or_create(name="Snyk")
        self.tool_conf, _ = Tool_Configuration.objects.get_or_create(
            name="Snyk_unittests",
            authentication_type="API",
            tool_type=tool_type,
            url="https://snyk.io/api/v1",
            api_key="test-api-key"
        )
        self.api_client = SnykAPI(self.tool_conf)

    def test_init(self):
        """Test SnykAPI initialization"""
        self.assertEqual(self.api_client.snyk_api_url, "https://snyk.io/api/v1")
        self.assertIn("DefectDojo", self.api_client.default_headers["User-Agent"])
        self.assertEqual(self.api_client.default_headers["authorization"], "test-api-key")
        self.assertIn("Token test-api-key", self.api_client.v1_headers["Authorization"])

    @mock.patch('requests.Session.get')
    def test_get_organizations(self, mock_get):
        """Test getting organizations"""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "orgs": [
                {"id": "org1", "name": "Organization 1"},
                {"id": "org2", "name": "Organization 2"}
            ]
        }
        mock_get.return_value = mock_response

        orgs = self.api_client.get_organizations()
        self.assertEqual(len(orgs), 2)
        self.assertEqual(orgs[0]["name"], "Organization 1")

    @mock.patch('requests.Session.get')
    def test_get_organizations_failure(self, mock_get):
        """Test handling of failed organization request"""
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 401
        mock_response.content.decode.return_value = "Unauthorized"
        mock_get.return_value = mock_response

        with self.assertRaises(Exception) as context:
            self.api_client.get_organizations()
        self.assertIn("Unable to get organizations", str(context.exception))
        self.assertIn("401", str(context.exception))

    @mock.patch('requests.Session.get')
    def test_get_organization(self, mock_get):
        """Test getting a specific organization"""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "slug": "test-org-name"
                }
            }
        }
        mock_get.return_value = mock_response

        org_name = self.api_client.get_organization("test-org-id")
        self.assertEqual(org_name, "test-org-name")

    @mock.patch('requests.Session.get')
    def test_get_organization_failure(self, mock_get):
        """Test handling of failed organization request"""
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 404
        mock_response.content.decode.return_value = "Not Found"
        mock_get.return_value = mock_response

        with self.assertRaises(Exception) as context:
            self.api_client.get_organization("non-existent-org")
        self.assertIn("Unable to get organization", str(context.exception))

    @mock.patch('requests.Session.get')
    def test_get_projects(self, mock_get):
        """Test getting projects for an organization"""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "meta": {
                "count": 5
            }
        }
        mock_get.return_value = mock_response

        project_count = self.api_client.get_projects("test-org-id")
        self.assertEqual(project_count, 5)

    @mock.patch('requests.Session.get')
    def test_get_issues(self, mock_get):
        """Test getting issues for an organization"""
        # Mock first page response
        mock_response_page1 = Mock()
        mock_response_page1.ok = True
        mock_response_page1.json.return_value = {
            "data": [
                {"id": "issue1", "type": "issue"},
                {"id": "issue2", "type": "issue"}
            ],
            "links": {
                "next": "https://snyk.io/api/v1/rest/orgs/test-org/issues?page=2"
            }
        }

        # Mock second page response (no next link)
        mock_response_page2 = Mock()
        mock_response_page2.ok = True
        mock_response_page2.json.return_value = {
            "data": [
                {"id": "issue3", "type": "issue"}
            ],
            "links": {}
        }

        mock_get.side_effect = [mock_response_page1, mock_response_page2]

        issues = self.api_client.get_issues("test-org-id")
        self.assertEqual(len(issues), 3)
        self.assertEqual(issues[0]["id"], "issue1")
        self.assertEqual(issues[2]["id"], "issue3")

    @mock.patch('requests.Session.get')
    def test_get_issue(self, mock_get):
        """Test getting a specific issue"""
        with (get_unit_tests_scans_path("api_snyk") / "single_issue.json").open(encoding="utf-8") as json_file:
            issue_data = json.load(json_file)

        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {"data": issue_data}
        mock_get.return_value = mock_response

        issue = self.api_client.get_issue("test-org-id", "test-issue-id")
        self.assertEqual(issue["id"], "10edba93-ee9d-4ef7-843a-77d1dad6c843")
        self.assertEqual(issue["attributes"]["title"], "Deserialization of Untrusted Data")

    @mock.patch('requests.Session.post')
    def test_ignore_issue(self, mock_post):
        """Test ignoring an issue - covers TODO in api_client.py line 197"""
        mock_response = Mock()
        mock_response.ok = True
        mock_post.return_value = mock_response

        self.api_client.ignore_issue(
            org_name="test-org",
            project_id="test-project",
            issue_name="test-issue",
            reason=IGNORE_REASON.NOT_VULNERABLE.value,
            notes="Test notes"
        )

        # Verify the correct endpoint and headers were used
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertIn("https://snyk.io/api/v1/org/test-org/project/test-project/ignore/test-issue", call_args[1]["url"])
        self.assertEqual(call_args[1]["headers"], self.api_client.v1_headers)
        
        # Verify the data payload
        expected_data = {
            "reasonType": IGNORE_REASON.NOT_VULNERABLE.value,
            "reason": "Test notes",
            "disregardIfFixable": False
        }
        self.assertEqual(call_args[1]["json"], expected_data)

    @mock.patch('requests.Session.post')
    def test_ignore_issue_failure(self, mock_post):
        """Test handling of failed ignore request"""
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 400
        mock_response.content.decode.return_value = "Bad Request"
        mock_post.return_value = mock_response

        with self.assertRaises(Exception) as context:
            self.api_client.ignore_issue("test-org", "test-project", "test-issue", "not-vulnerable")
        self.assertIn("Unable to ignore issue", str(context.exception))

    @mock.patch('requests.Session.delete')
    def test_unignore_issue(self, mock_delete):
        """Test unignoring an issue - covers TODO in api_client.py line 218"""
        mock_response = Mock()
        mock_response.ok = True
        mock_delete.return_value = mock_response

        self.api_client.unignore_issue(
            org_name="test-org",
            project_id="test-project",
            issue_name="test-issue"
        )

        # Verify the correct endpoint and headers were used
        mock_delete.assert_called_once()
        call_args = mock_delete.call_args
        self.assertIn("https://snyk.io/api/v1/org/test-org/project/test-project/ignore/test-issue", call_args[1]["url"])
        self.assertEqual(call_args[1]["headers"], self.api_client.v1_headers)

    @mock.patch('requests.Session.delete')
    def test_unignore_issue_failure(self, mock_delete):
        """Test handling of failed unignore request"""
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 404
        mock_response.content.decode.return_value = "Not Found"
        mock_delete.return_value = mock_response

        with self.assertRaises(Exception) as context:
            self.api_client.unignore_issue("test-org", "test-project", "test-issue")
        self.assertIn("Unable to unignore issue", str(context.exception))

    @mock.patch('requests.Session.get')
    def test_test_connection(self, mock_get):
        """Test connection testing"""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "name": "Test User"
                }
            }
        }
        mock_get.return_value = mock_response

        result = self.api_client.test_connection()
        self.assertIn("Successfully connected to Snyk as user: Test User", result)

    @mock.patch('requests.Session.get')
    def test_test_connection_failure(self, mock_get):
        """Test connection test failure"""
        mock_response = Mock()
        mock_response.ok = False
        mock_response.status_code = 401
        mock_response.content.decode.return_value = "Unauthorized"
        mock_get.return_value = mock_response

        with self.assertRaises(Exception) as context:
            self.api_client.test_connection()
        self.assertIn("Unable to connect to Snyk", str(context.exception))

    @mock.patch('requests.Session.get')
    def test_test_connection_non_json(self, mock_get):
        """Test connection test with non-JSON response"""
        mock_response = Mock()
        mock_response.ok = True
        mock_response.json.side_effect = requests.exceptions.JSONDecodeError("msg", "doc", 0)
        mock_response.status_code = 200
        mock_response.reason = "OK"
        mock_response.text = "Non-JSON response"
        mock_get.return_value = mock_response

        with self.assertRaises(Exception) as context:
            self.api_client.test_connection()
        self.assertIn("response doesn't contain", str(context.exception))

    @mock.patch.object(SnykAPI, 'get_organization')
    @mock.patch.object(SnykAPI, 'get_projects')
    def test_test_product_connection(self, mock_get_projects, mock_get_organization):
        """Test product connection testing"""
        mock_get_organization.return_value = "test-org-name"
        mock_get_projects.return_value = 5

        # Create a mock API scan configuration
        config = Mock()
        config.service_key_1 = "test-org-id"
        config.service_key_2 = "test-project-id"

        result = self.api_client.test_product_connection(config)
        self.assertIn("Successfully connected to Snyk organization 'test-org-name' with 5 projects", result)

    def test_get_id_to_org_mapping_cache(self):
        """Test organization ID to name mapping with caching"""
        with mock.patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = {
                "data": [
                    {"id": "org1", "attributes": {"slug": "organization-1"}},
                    {"id": "org2", "attributes": {"slug": "organization-2"}}
                ]
            }
            mock_get.return_value = mock_response

            # First call should make HTTP request
            mapping1 = self.api_client.get_id_to_org_mapping()
            self.assertEqual(mapping1["org1"], "organization-1")
            self.assertEqual(mock_get.call_count, 1)

            # Second call should use cache
            mapping2 = self.api_client.get_id_to_org_mapping()
            self.assertEqual(mapping2["org1"], "organization-1")
            self.assertEqual(mock_get.call_count, 1)  # Should still be 1 due to caching

    def test_ignore_reason_enum(self):
        """Test IGNORE_REASON enum values"""
        self.assertEqual(IGNORE_REASON.NOT_VULNERABLE.value, "not-vulnerable")
        self.assertEqual(IGNORE_REASON.IGNORE_PERMANENTLY.value, "temporary-ignore")
        self.assertEqual(IGNORE_REASON.WONT_FIX.value, "wont-fix")
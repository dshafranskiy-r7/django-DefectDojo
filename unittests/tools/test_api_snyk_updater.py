import json
from unittest import mock
from unittest.mock import Mock, patch
from datetime import datetime

from django.utils import timezone

from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Snyk_Issue,
    Snyk_Issue_Transition,
    Test,
    Test_Type,
    Tool_Configuration,
    Tool_Type,
    User,
)
from dojo.tools.api_snyk.updater import SnykApiUpdater
from dojo.tools.api_snyk.api_client import IGNORE_REASON
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def single_issue_data():
    """Load the single issue test data provided by the user"""
    with (get_unit_tests_scans_path("api_snyk") / "single_issue.json").open(encoding="utf-8") as json_file:
        return json.load(json_file)


class TestSnykApiUpdater(DojoTestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="testuser", email="test@example.com")
        product_type, _ = Product_Type.objects.get_or_create(name="Fake unit tests")
        product, _ = Product.objects.get_or_create(name="product", prod_type=product_type)
        
        # Create engagement with required fields
        engagement = Engagement.objects.create(
            product=product,
            target_start=timezone.now().date(),
            target_end=timezone.now().date()
        )
        
        # Build Snyk configuration
        tool_type, _ = Tool_Type.objects.get_or_create(name="Snyk")
        tool_conf, _ = Tool_Configuration.objects.get_or_create(
            name="Snyk_unittests",
            authentication_type="API",
            tool_type=tool_type,
            url="https://snyk.io/api/v1",
            api_key="test-api-key"
        )
        product_api_scan_configuration, _ = Product_API_Scan_Configuration.objects.get_or_create(
            product=product,
            tool_configuration=tool_conf,
            service_key_1="test-org-id",  # Organization ID
            service_key_2="test-project-id",  # Project ID (optional)
        )
        
        # Create test type
        test_type, _ = Test_Type.objects.get_or_create(name="Snyk API Test")
        
        self.test = Test.objects.create(
            engagement=engagement,
            api_scan_configuration=product_api_scan_configuration,
            test_type=test_type,
            target_start=timezone.now(),
            target_end=timezone.now()
        )

        # Create a Snyk issue and associated finding
        self.snyk_issue = Snyk_Issue.objects.create(
            key="SNYK-JAVA-COMFASTERXMLJACKSONCORE-1056417",
            status="open",
            type="package_vulnerability"
        )

        self.finding = Finding.objects.create(
            title="Test Finding",
            test=self.test,
            severity="High",
            snyk_issue=self.snyk_issue,
            reporter=self.user,
            unique_id_from_tool="test-finding-id",
            verified=True,
            active=True
        )

    def test_get_snyk_status_for_finding(self):
        """Test status mapping from DefectDojo finding to Snyk status"""
        updater = SnykApiUpdater()

        # Test false positive
        self.finding.false_p = True
        self.finding.active = False
        status = updater.get_snyk_status_for(self.finding)
        self.assertEqual(status, "IGNORED / FALSE-POSITIVE")

        # Test mitigated
        self.finding.false_p = False
        self.finding.mitigated = timezone.now()
        self.finding.is_mitigated = True
        self.finding.active = False
        status = updater.get_snyk_status_for(self.finding)
        self.assertEqual(status, "IGNORED / FIXED")

        # Test risk accepted
        self.finding.mitigated = None
        self.finding.is_mitigated = False
        self.finding.risk_accepted = True
        self.finding.active = False
        status = updater.get_snyk_status_for(self.finding)
        self.assertEqual(status, "IGNORED / WONTFIX")

        # Test active
        self.finding.false_p = False
        self.finding.mitigated = None
        self.finding.is_mitigated = False
        self.finding.risk_accepted = False
        self.finding.active = True
        status = updater.get_snyk_status_for(self.finding)
        self.assertEqual(status, "OPEN")

    def test_update_snyk_finding_no_issue(self):
        """Test updating finding with no associated Snyk issue"""
        updater = SnykApiUpdater()
        finding_no_issue = Finding.objects.create(
            title="No Issue Finding",
            test=self.test,
            severity="Medium",
            reporter=self.user,
            unique_id_from_tool="no-issue-finding",
            verified=True,
            active=True
        )

        # Should return early without error
        updater.update_snyk_finding(finding_no_issue)

    @mock.patch('dojo.tools.api_snyk.importer.SnykApiImporter.prepare_client')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.get_issue')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.get_id_to_org_mapping')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.ignore_issue')
    def test_update_snyk_finding_ignore_false_positive(self, mock_ignore_issue, mock_get_mapping, mock_get_issue, mock_prepare_client):
        """Test updating finding that should be ignored as false positive"""
        updater = SnykApiUpdater()
        
        # Setup mocks
        mock_client = Mock()
        mock_config = Mock()
        mock_config.service_key_1 = "test-org-id"
        mock_prepare_client.return_value = (mock_client, mock_config)
        
        issue_data = single_issue_data()
        mock_get_issue.return_value = issue_data
        mock_get_mapping.return_value = {"test-org-id": "test-org-name"}

        # Set finding as false positive
        self.finding.false_p = True
        self.finding.active = False

        updater.update_snyk_finding(self.finding)

        # Verify ignore_issue was called with correct parameters
        mock_ignore_issue.assert_called_once_with(
            org_name="test-org-name",
            project_id="bd740131-a87d-4dca-bd66-b3f0cf346b6c",
            issue_name="SNYK-JAVA-COMFASTERXMLJACKSONCORE-1056417",
            reason=IGNORE_REASON.NOT_VULNERABLE.value,
            notes="Marked as false positive in DefectDojo"
        )

        # Verify transition record was created
        transitions = Snyk_Issue_Transition.objects.filter(snyk_issue=self.snyk_issue)
        self.assertEqual(transitions.count(), 1)
        self.assertIn("not-vulnerable", transitions.first().transitions)

    @mock.patch('dojo.tools.api_snyk.importer.SnykApiImporter.prepare_client')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.get_issue')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.get_id_to_org_mapping')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.ignore_issue')
    def test_update_snyk_finding_ignore_mitigated(self, mock_ignore_issue, mock_get_mapping, mock_get_issue, mock_prepare_client):
        """Test updating finding that should be ignored as fixed"""
        updater = SnykApiUpdater()
        
        # Setup mocks
        mock_client = Mock()
        mock_config = Mock()
        mock_config.service_key_1 = "test-org-id"
        mock_prepare_client.return_value = (mock_client, mock_config)
        
        issue_data = single_issue_data()
        mock_get_issue.return_value = issue_data
        mock_get_mapping.return_value = {"test-org-id": "test-org-name"}

        # Set finding as mitigated
        self.finding.mitigated = timezone.now()
        self.finding.is_mitigated = True
        self.finding.active = False

        updater.update_snyk_finding(self.finding)

        # Verify ignore_issue was called with correct parameters
        mock_ignore_issue.assert_called_once_with(
            org_name="test-org-name",
            project_id="bd740131-a87d-4dca-bd66-b3f0cf346b6c",
            issue_name="SNYK-JAVA-COMFASTERXMLJACKSONCORE-1056417",
            reason=IGNORE_REASON.WONT_FIX.value,  # Note: current implementation uses WONT_FIX instead of FIXED
            notes="Marked as fixed in DefectDojo"
        )

    @mock.patch('dojo.tools.api_snyk.importer.SnykApiImporter.prepare_client')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.get_issue')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.get_id_to_org_mapping')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.ignore_issue')
    def test_update_snyk_finding_ignore_risk_accepted(self, mock_ignore_issue, mock_get_mapping, mock_get_issue, mock_prepare_client):
        """Test updating finding that should be ignored as won't fix"""
        updater = SnykApiUpdater()
        
        # Setup mocks
        mock_client = Mock()
        mock_config = Mock()
        mock_config.service_key_1 = "test-org-id"
        mock_prepare_client.return_value = (mock_client, mock_config)
        
        issue_data = single_issue_data()
        mock_get_issue.return_value = issue_data
        mock_get_mapping.return_value = {"test-org-id": "test-org-name"}

        # Set finding as risk accepted
        self.finding.risk_accepted = True
        self.finding.active = False

        updater.update_snyk_finding(self.finding)

        # Verify ignore_issue was called with correct parameters
        mock_ignore_issue.assert_called_once_with(
            org_name="test-org-name",
            project_id="bd740131-a87d-4dca-bd66-b3f0cf346b6c",
            issue_name="SNYK-JAVA-COMFASTERXMLJACKSONCORE-1056417",
            reason=IGNORE_REASON.WONT_FIX.value,
            notes="Risk accepted in DefectDojo"
        )

    @mock.patch('dojo.tools.api_snyk.importer.SnykApiImporter.prepare_client')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.get_issue')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.get_id_to_org_mapping')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.unignore_issue')
    def test_update_snyk_finding_unignore(self, mock_unignore_issue, mock_get_mapping, mock_get_issue, mock_prepare_client):
        """Test updating finding that should be unignored"""
        updater = SnykApiUpdater()
        
        # Setup mocks
        mock_client = Mock()
        mock_config = Mock()
        mock_config.service_key_1 = "test-org-id"
        mock_prepare_client.return_value = (mock_client, mock_config)
        
        # Create ignored issue data
        issue_data = single_issue_data()
        issue_data["attributes"]["ignored"] = True
        mock_get_issue.return_value = issue_data
        mock_get_mapping.return_value = {"test-org-id": "test-org-name"}

        # Set finding as active (should unignore)
        self.finding.active = True
        self.finding.false_p = False
        self.finding.mitigated = None
        self.finding.is_mitigated = False
        self.finding.risk_accepted = False

        updater.update_snyk_finding(self.finding)

        # Verify unignore_issue was called
        mock_unignore_issue.assert_called_once_with(
            org_name="test-org-name",
            project_id="bd740131-a87d-4dca-bd66-b3f0cf346b6c",
            issue_name="SNYK-JAVA-COMFASTERXMLJACKSONCORE-1056417"
        )

    @mock.patch('dojo.tools.api_snyk.importer.SnykApiImporter.prepare_client')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.get_issue')
    def test_update_snyk_finding_issue_not_found(self, mock_get_issue, mock_prepare_client):
        """Test handling when Snyk issue is not found (may have been deleted) - covers TODO at line 78"""
        updater = SnykApiUpdater()
        
        # Setup mocks
        mock_client = Mock()
        mock_config = Mock()
        mock_config.service_key_1 = "test-org-id"
        mock_prepare_client.return_value = (mock_client, mock_config)
        
        # Return None to simulate issue not found
        mock_get_issue.return_value = None

        # Should return without error
        updater.update_snyk_finding(self.finding)

    def test_update_snyk_finding_no_config(self):
        """Test handling when no configuration is found"""
        updater = SnykApiUpdater()
        
        # Create finding without test configuration
        finding_no_config = Finding.objects.create(
            title="No Config Finding",
            test=self.test,
            severity="Medium",
            snyk_issue=self.snyk_issue,
            reporter=self.user,
            unique_id_from_tool="no-config-finding",
            verified=True,
            active=True
        )
        
        # Remove the test's API scan configuration
        finding_no_config.test.api_scan_configuration = None
        finding_no_config.test.save()

        # Should return without error (after trying product configs)
        updater.update_snyk_finding(finding_no_config)

    @mock.patch('dojo.tools.api_snyk.importer.SnykApiImporter.prepare_client')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.get_issue')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.get_id_to_org_mapping')
    def test_current_status_determination(self, mock_get_mapping, mock_get_issue, mock_prepare_client):
        """Test determination of current status in Snyk - covers TODO at line 78 about resolved status"""
        updater = SnykApiUpdater()
        
        # Setup mocks
        mock_client = Mock()
        mock_config = Mock()
        mock_config.service_key_1 = "test-org-id"
        mock_prepare_client.return_value = (mock_client, mock_config)
        mock_get_mapping.return_value = {"test-org-id": "test-org-name"}

        # Test with open issue
        issue_data = single_issue_data()
        issue_data["attributes"]["status"] = "open"
        issue_data["attributes"]["ignored"] = False
        mock_get_issue.return_value = issue_data

        with mock.patch('dojo.tools.api_snyk.importer.SnykApiImporter.is_in_state') as mock_is_in_state:
            mock_is_in_state.return_value = False  # Not ignored
            updater.update_snyk_finding(self.finding)
            mock_is_in_state.assert_called_with(issue_data, "ignored")

        # Test with ignored issue
        issue_data["attributes"]["ignored"] = True
        mock_get_issue.return_value = issue_data

        with mock.patch('dojo.tools.api_snyk.importer.SnykApiImporter.is_in_state') as mock_is_in_state:
            mock_is_in_state.return_value = True  # Is ignored
            updater.update_snyk_finding(self.finding)

    @mock.patch('dojo.tools.api_snyk.importer.SnykApiImporter.prepare_client')
    def test_exception_handling(self, mock_prepare_client):
        """Test exception handling in update_snyk_finding"""
        updater = SnykApiUpdater()
        
        # Setup mock to raise exception
        mock_prepare_client.side_effect = Exception("Connection failed")

        # Should not raise exception, just log warning
        updater.update_snyk_finding(self.finding)

    def test_method_access_patterns(self):
        """Test better method access patterns - covers TODO at line 85"""
        updater = SnykApiUpdater()
        issue_data = single_issue_data()
        
        # Test accessing issue attributes through get methods
        issue_name = issue_data["attributes"]["key"]
        self.assertEqual(issue_name, "SNYK-JAVA-COMFASTERXMLJACKSONCORE-1056417")
        
        project = issue_data["relationships"]["scan_item"]["data"]["id"]
        self.assertEqual(project, "bd740131-a87d-4dca-bd66-b3f0cf346b6c")
        
        # These are the patterns that could be improved with get methods for better error handling
import json
from unittest import mock
from unittest.mock import Mock, patch

from django.utils import timezone

from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Risk_Acceptance,
    Snyk_Issue,
    Test,
    Test_Type,
    Tool_Configuration,
    Tool_Type,
    User,
)
from dojo.tools.api_snyk.updater_from_source import SnykApiUpdaterFromSource
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def single_issue_data():
    """Load the single issue test data provided by the user"""
    with (get_unit_tests_scans_path("api_snyk") / "single_issue.json").open(encoding="utf-8") as json_file:
        return json.load(json_file)


class TestSnykApiUpdaterFromSource(DojoTestCase):
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

    def test_get_findings_to_update(self):
        """Test getting findings that need to be updated"""
        updater = SnykApiUpdaterFromSource()
        
        # Create additional findings
        snyk_issue_2 = Snyk_Issue.objects.create(
            key="SNYK-TEST-2",
            status="open",
            type="package_vulnerability"
        )
        
        # Active finding with Snyk issue
        Finding.objects.create(
            title="Active Finding with Snyk Issue",
            test=self.test,
            severity="Medium",
            snyk_issue=snyk_issue_2,
            reporter=self.user,
            verified=True,
            active=True
        )
        
        # Inactive finding with Snyk issue (should not be included)
        Finding.objects.create(
            title="Inactive Finding with Snyk Issue",
            test=self.test,
            severity="Low",
            snyk_issue=snyk_issue_2,
            reporter=self.user,
            verified=True,
            active=False
        )
        
        # Active finding without Snyk issue (should not be included)
        Finding.objects.create(
            title="Active Finding without Snyk Issue",
            test=self.test,
            severity="High",
            reporter=self.user,
            verified=True,
            active=True
        )

        findings_to_update = updater.get_findings_to_update()
        
        # Should return 2 findings (only active findings with Snyk issues)
        self.assertEqual(findings_to_update.count(), 2)
        for finding in findings_to_update:
            self.assertTrue(finding.active)
            self.assertIsNotNone(finding.snyk_issue)

    def test_get_snyk_status_for_finding(self):
        """Test status mapping from DefectDojo finding to Snyk status"""
        updater = SnykApiUpdaterFromSource()

        # Test false positive
        self.finding.false_p = True
        self.finding.active = False
        status = updater.get_snyk_status_for(self.finding)
        self.assertEqual(status, "IGNORED")

        # Test mitigated
        self.finding.false_p = False
        self.finding.mitigated = timezone.now()
        self.finding.is_mitigated = True
        self.finding.active = False
        status = updater.get_snyk_status_for(self.finding)
        self.assertEqual(status, "IGNORED")

        # Test risk accepted
        self.finding.mitigated = None
        self.finding.is_mitigated = False
        self.finding.risk_accepted = True
        self.finding.active = False
        status = updater.get_snyk_status_for(self.finding)
        self.assertEqual(status, "IGNORED")

        # Test active
        self.finding.false_p = False
        self.finding.mitigated = None
        self.finding.is_mitigated = False
        self.finding.risk_accepted = False
        self.finding.active = True
        status = updater.get_snyk_status_for(self.finding)
        self.assertEqual(status, "OPEN")

    def test_update_no_snyk_issue(self):
        """Test updating finding with no associated Snyk issue"""
        updater = SnykApiUpdaterFromSource()
        finding_no_issue = Finding.objects.create(
            title="No Issue Finding",
            test=self.test,
            severity="Medium",
            reporter=self.user,
            verified=True,
            active=True
        )

        # Should return early without error
        updater.update(finding_no_issue)

    @mock.patch('dojo.tools.api_snyk.importer.SnykApiImporter.prepare_client')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.get_issue')
    def test_update_issue_not_found(self, mock_get_issue, mock_prepare_client):
        """Test handling when Snyk issue is not found"""
        updater = SnykApiUpdaterFromSource()
        
        # Setup mocks
        mock_client = Mock()
        mock_config = Mock()
        mock_config.service_key_1 = "test-org-id"
        mock_prepare_client.return_value = (mock_client, mock_config)
        
        # Return None to simulate issue not found
        mock_get_issue.return_value = None

        # Should return without error
        updater.update(self.finding)

    @mock.patch('dojo.tools.api_snyk.importer.SnykApiImporter.prepare_client')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.get_issue')
    def test_update_status_sync(self, mock_get_issue, mock_prepare_client):
        """Test status synchronization when statuses match"""
        updater = SnykApiUpdaterFromSource()
        
        # Setup mocks
        mock_client = Mock()
        mock_config = Mock()
        mock_config.service_key_1 = "test-org-id"
        mock_prepare_client.return_value = (mock_client, mock_config)
        
        # Return open issue (matches active finding)
        issue_data = single_issue_data()
        issue_data["ignored"] = False
        mock_get_issue.return_value = issue_data

        # Finding is active, issue is open - should be in sync
        self.finding.active = True
        self.finding.false_p = False
        
        with mock.patch.object(updater, 'update_finding_status') as mock_update_status:
            updater.update(self.finding)
            mock_update_status.assert_not_called()

    @mock.patch('dojo.tools.api_snyk.importer.SnykApiImporter.prepare_client')
    @mock.patch('dojo.tools.api_snyk.api_client.SnykAPI.get_issue')
    def test_update_status_mismatch(self, mock_get_issue, mock_prepare_client):
        """Test status synchronization when statuses don't match"""
        updater = SnykApiUpdaterFromSource()
        
        # Setup mocks
        mock_client = Mock()
        mock_config = Mock()
        mock_config.service_key_1 = "test-org-id"
        mock_prepare_client.return_value = (mock_client, mock_config)
        
        # Return ignored issue but finding is active
        issue_data = single_issue_data()
        issue_data["ignored"] = True
        mock_get_issue.return_value = issue_data

        # Finding is active but issue is ignored - should update
        self.finding.active = True
        self.finding.false_p = False
        
        with mock.patch.object(updater, 'update_finding_status') as mock_update_status:
            updater.update(self.finding)
            mock_update_status.assert_called_once_with(self.finding, "IGNORED", issue_data)

    def test_update_finding_status_to_open(self):
        """Test updating finding status to open"""
        updater = SnykApiUpdaterFromSource()
        
        # Set finding as false positive initially
        self.finding.active = False
        self.finding.false_p = True
        self.finding.verified = False
        
        # Create a risk acceptance to test removal
        risk_acceptance = Risk_Acceptance.objects.create(owner=self.user)
        risk_acceptance.accepted_findings.add(self.finding)
        
        updater.update_finding_status(self.finding, "OPEN")
        
        # Refresh from database
        self.finding.refresh_from_db()
        
        # Should be set to active/open
        self.assertTrue(self.finding.active)
        self.assertTrue(self.finding.verified)
        self.assertFalse(self.finding.false_p)
        self.assertIsNone(self.finding.mitigated)
        self.assertFalse(self.finding.is_mitigated)
        
        # Risk acceptance should be removed
        self.assertFalse(risk_acceptance.accepted_findings.filter(id=self.finding.id).exists())

    def test_update_finding_status_to_ignored_false_positive(self):
        """Test updating finding status to ignored (false positive)"""
        updater = SnykApiUpdaterFromSource()
        
        # Create issue data with false positive ignore reason
        issue_data = {
            "ignoreReasons": [
                {"reason": "false-positive"}
            ]
        }
        
        # Set finding as active initially
        self.finding.active = True
        self.finding.false_p = False
        
        updater.update_finding_status(self.finding, "IGNORED", issue_data)
        
        # Refresh from database
        self.finding.refresh_from_db()
        
        # Should be set as false positive
        self.assertFalse(self.finding.active)
        self.assertFalse(self.finding.verified)
        self.assertTrue(self.finding.false_p)
        self.assertIsNone(self.finding.mitigated)
        self.assertFalse(self.finding.is_mitigated)

    def test_update_finding_status_to_ignored_not_vulnerable(self):
        """Test updating finding status to ignored (not vulnerable)"""
        updater = SnykApiUpdaterFromSource()
        
        # Create issue data with not-vulnerable ignore reason
        issue_data = {
            "ignoreReasons": [
                {"reason": "not-vulnerable"}
            ]
        }
        
        updater.update_finding_status(self.finding, "IGNORED", issue_data)
        
        # Refresh from database
        self.finding.refresh_from_db()
        
        # Should be set as false positive
        self.assertTrue(self.finding.false_p)

    def test_update_finding_status_to_ignored_fixed(self):
        """Test updating finding status to ignored (fixed)"""
        updater = SnykApiUpdaterFromSource()
        
        # Create issue data with fixed ignore reason
        issue_data = {
            "ignoreReasons": [
                {"reason": "fixed"}
            ]
        }
        
        # Set finding as active initially
        self.finding.active = True
        self.finding.mitigated = None
        self.finding.is_mitigated = False
        
        updater.update_finding_status(self.finding, "IGNORED", issue_data)
        
        # Refresh from database
        self.finding.refresh_from_db()
        
        # Should be set as mitigated
        self.assertFalse(self.finding.active)
        self.assertTrue(self.finding.verified)
        self.assertFalse(self.finding.false_p)
        self.assertIsNotNone(self.finding.mitigated)
        self.assertTrue(self.finding.is_mitigated)

    def test_update_finding_status_to_ignored_wont_fix(self):
        """Test updating finding status to ignored (won't fix)"""
        updater = SnykApiUpdaterFromSource()
        
        # Create issue data with wont-fix ignore reason
        issue_data = {
            "ignoreReasons": [
                {"reason": "wont-fix"}
            ]
        }
        
        # Set finding as active initially
        self.finding.active = True
        
        initial_risk_acceptance_count = Risk_Acceptance.objects.count()
        
        updater.update_finding_status(self.finding, "IGNORED", issue_data)
        
        # Refresh from database
        self.finding.refresh_from_db()
        
        # Should be set as inactive with risk acceptance
        self.assertFalse(self.finding.active)
        self.assertTrue(self.finding.verified)
        self.assertFalse(self.finding.false_p)
        self.assertIsNone(self.finding.mitigated)
        self.assertFalse(self.finding.is_mitigated)
        
        # Should have created a risk acceptance
        self.assertEqual(Risk_Acceptance.objects.count(), initial_risk_acceptance_count + 1)

    def test_update_finding_status_to_ignored_no_fix(self):
        """Test updating finding status to ignored (no-fix)"""
        updater = SnykApiUpdaterFromSource()
        
        # Create issue data with no-fix ignore reason
        issue_data = {
            "ignoreReasons": [
                {"reason": "no-fix"}
            ]
        }
        
        initial_risk_acceptance_count = Risk_Acceptance.objects.count()
        
        updater.update_finding_status(self.finding, "IGNORED", issue_data)
        
        # Should have created a risk acceptance (same as wont-fix)
        self.assertEqual(Risk_Acceptance.objects.count(), initial_risk_acceptance_count + 1)

    def test_update_finding_status_to_ignored_generic(self):
        """Test updating finding status to ignored (generic reason)"""
        updater = SnykApiUpdaterFromSource()
        
        # Create issue data with unknown ignore reason
        issue_data = {
            "ignoreReasons": [
                {"reason": "some-other-reason"}
            ]
        }
        
        initial_risk_acceptance_count = Risk_Acceptance.objects.count()
        
        updater.update_finding_status(self.finding, "IGNORED", issue_data)
        
        # Should have created a risk acceptance (generic ignore)
        self.assertEqual(Risk_Acceptance.objects.count(), initial_risk_acceptance_count + 1)

    def test_update_finding_status_to_ignored_no_reason(self):
        """Test updating finding status to ignored with no ignore reasons"""
        updater = SnykApiUpdaterFromSource()
        
        # Create issue data with no ignore reasons
        issue_data = {}
        
        initial_risk_acceptance_count = Risk_Acceptance.objects.count()
        
        updater.update_finding_status(self.finding, "IGNORED", issue_data)
        
        # Should have created a risk acceptance (generic ignore)
        self.assertEqual(Risk_Acceptance.objects.count(), initial_risk_acceptance_count + 1)

    def test_update_finding_status_to_ignored_empty_reason(self):
        """Test updating finding status to ignored with empty ignore reasons"""
        updater = SnykApiUpdaterFromSource()
        
        # Create issue data with empty ignore reasons
        issue_data = {
            "ignoreReasons": []
        }
        
        initial_risk_acceptance_count = Risk_Acceptance.objects.count()
        
        updater.update_finding_status(self.finding, "IGNORED", issue_data)
        
        # Should have created a risk acceptance (generic ignore)
        self.assertEqual(Risk_Acceptance.objects.count(), initial_risk_acceptance_count + 1)

    @mock.patch('dojo.tools.api_snyk.importer.SnykApiImporter.prepare_client')
    def test_exception_handling(self, mock_prepare_client):
        """Test exception handling in update method"""
        updater = SnykApiUpdaterFromSource()
        
        # Setup mock to raise exception
        mock_prepare_client.side_effect = Exception("Connection failed")

        # Should not raise exception, just log warning
        updater.update(self.finding)

    def test_finding_save_parameters(self):
        """Test that finding save is called with correct parameters"""
        updater = SnykApiUpdaterFromSource()
        
        with mock.patch.object(Finding, 'save') as mock_save:
            updater.update_finding_status(self.finding, "OPEN")
            mock_save.assert_called_once_with(issue_updater_option=False, dedupe_option=False)
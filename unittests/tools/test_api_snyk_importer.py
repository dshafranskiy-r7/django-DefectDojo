import json
from unittest import mock

from dojo.models import (
    Engagement,
    Product,
    Product_API_Scan_Configuration,
    Product_Type,
    Test,
    Tool_Configuration,
    Tool_Type,
)
from dojo.tools.api_snyk.importer import SnykApiImporter
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def dummy_organization(self, *args, **kwargs):
    with (get_unit_tests_scans_path("api_snyk") / "organization.json").open(encoding="utf-8") as json_file:
        return json.load(json_file)


def dummy_issues(self, *args, **kwargs):
    with (get_unit_tests_scans_path("api_snyk") / "issues.json").open(encoding="utf-8") as json_file:
        return json.load(json_file)

class TestApiSnykImporter(DojoTestCase):
    def setUp(self):
        product_type, _ = Product_Type.objects.get_or_create(name="Fake unit tests")
        product, _ = Product.objects.get_or_create(name="product", prod_type=product_type)
        engagement = Engagement(product=product)
        # build Snyk conf (the parser need it)
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
        self.test = Test(
            engagement=engagement,
            api_scan_configuration=product_api_scan_configuration,
        )

    @mock.patch("dojo.tools.api_snyk.api_client.SnykAPI.get_organization")
    @mock.patch("dojo.tools.api_snyk.api_client.SnykAPI.get_issues")
    @mock.patch("dojo.tools.api_snyk.api_client.SnykAPI.get_id_to_org_mapping")
    def test_import_issues(self, mock_get_issues, mock_get_organization, mock_get_id_to_org_mapping):
        mock_get_organization.side_effect = dummy_organization
        mock_get_issues.side_effect = dummy_issues
        mock_get_id_to_org_mapping.side_effect = lambda: {"test-org-id": "test-org-name"}

        importer = SnykApiImporter()
        findings = importer.import_issues(self.test)
        print(len(findings))

        # Should return 2 findings (excluding the ignored one)
        self.assertEqual(2, len(findings))

        # Test conversion methods
        self.assertEqual("Critical", importer.convert_snyk_severity("critical"))
        self.assertEqual("High", importer.convert_snyk_severity("high"))
        self.assertEqual("Medium", importer.convert_snyk_severity("medium"))
        self.assertEqual("Low", importer.convert_snyk_severity("low"))
        self.assertEqual("Info", importer.convert_snyk_severity("unknown"))

    def test_is_ignored(self):
        importer = SnykApiImporter()

        self.assertTrue(importer.is_ignored({"ignored": True}))
        self.assertFalse(importer.is_ignored({"ignored": False}))
        self.assertFalse(importer.is_ignored({}))

    def test_is_patched(self):
        importer = SnykApiImporter()

        self.assertTrue(importer.is_patched({"patched": True}))
        self.assertFalse(importer.is_patched({"patched": False}))
        self.assertFalse(importer.is_patched({}))
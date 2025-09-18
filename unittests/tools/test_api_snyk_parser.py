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
from dojo.tools.api_snyk.parser import ApiSnykParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def dummy_organization(*args, **kwargs):
    return { "org": { "id": "test-org-id", "name": "test-org-name" } }


def dummy_issues(*args, **kwargs):
    with (get_unit_tests_scans_path("api_snyk") / "issues.json").open(encoding="utf-8") as json_file:
        return json.load(json_file)

def empty_list(*args, **kwargs):
    return []

def dummy_mapping(*args, **kwargs):
    return {"test-org-id": "test-org-name"}


class TestApiSnykParser(DojoTestCase):
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

    def test_get_scan_types(self):
        parser = ApiSnykParser()
        scan_types = parser.get_scan_types()
        self.assertIn("Snyk API Import", scan_types)

    def test_get_label_for_scan_types(self):
        parser = ApiSnykParser()
        label = parser.get_label_for_scan_types("Snyk API Import")
        self.assertEqual("Snyk API Import", label)

    def test_get_description_for_scan_types(self):
        parser = ApiSnykParser()
        description = parser.get_description_for_scan_types("Snyk API Import")
        self.assertIn("Snyk findings can be directly imported", description)

    def test_requires_file(self):
        parser = ApiSnykParser()
        self.assertFalse(parser.requires_file("Snyk API Import"))

    def test_requires_tool_type(self):
        parser = ApiSnykParser()
        tool_type = parser.requires_tool_type("Snyk API Import")
        self.assertEqual("Snyk", tool_type)

    def test_api_scan_configuration_hint(self):
        parser = ApiSnykParser()
        hint = parser.api_scan_configuration_hint()
        self.assertIn("Service key 1", hint)
        self.assertIn("organization ID", hint)

    @mock.patch("dojo.tools.api_snyk.api_client.SnykAPI.get_issues")
    @mock.patch("dojo.tools.api_snyk.api_client.SnykAPI.get_id_to_org_mapping")
    def test_get_findings(self, mock_get_id_to_org_mapping, mock_get_issues):
        mock_get_issues.side_effect = dummy_issues
        mock_get_id_to_org_mapping.side_effect = dummy_mapping
        # mock_get_organization.side_effect = dummy_organization

        parser = ApiSnykParser()
        findings = parser.get_findings(None, self.test)

        # Should return 2 findings (excluding the ignored one)
        self.assertEqual(2, len(findings))

        # Check first finding (high severity)
        finding = findings[0]
        self.assertEqual("Prototype Pollution", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertEqual("lodash", finding.component_name)
        self.assertEqual("4.17.15", finding.component_version)
        self.assertEqual(1321, finding.cwe)
        self.assertEqual("SNYK-JS-LODASH-567746", finding.unique_id_from_tool)
        self.assertTrue(finding.verified)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.false_p)

        # Check second finding (medium severity)
        finding = findings[1]
        self.assertEqual("Regular Expression Denial of Service (ReDoS)", finding.title)
        self.assertEqual("Medium", finding.severity)
        self.assertEqual("axios", finding.component_name)
        self.assertEqual("0.21.1", finding.component_version)
        self.assertEqual(1333, finding.cwe)
        self.assertEqual("SNYK-JS-AXIOS-2391665", finding.unique_id_from_tool)
        self.assertFalse(finding.verified)  # Medium severity is not auto-verified
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.false_p)

    @mock.patch("dojo.tools.api_snyk.api_client.SnykAPI.get_issues")
    @mock.patch("dojo.tools.api_snyk.api_client.SnykAPI.get_id_to_org_mapping")
    def test_get_findings_empty(self, mock_get_id_to_org_mapping, mock_get_issues):
        mock_get_issues.return_value = {"issues": []}
        mock_get_id_to_org_mapping.side_effect = dummy_mapping

        parser = ApiSnykParser()
        findings = parser.get_findings(None, self.test)

        self.assertEqual(0, len(findings))
from .importer import SnykApiImporter

SCAN_SNYK_API = "Snyk API Import"


class ApiSnykParser:
    def get_scan_types(self):
        return [SCAN_SNYK_API]

    def get_label_for_scan_types(self, scan_type):
        return SCAN_SNYK_API

    def get_description_for_scan_types(self, scan_type):
        return (
            "Snyk findings can be directly imported using the Snyk API. An API Scan Configuration has "
            "to be setup in the Product."
        )

    def requires_file(self, scan_type):
        return False

    def requires_tool_type(self, scan_type):
        return "Snyk"

    def api_scan_configuration_hint(self):
        return (
            "the field <b>Service key 1</b> has to be set with the Snyk organization ID. <b>Service key 2</b> "
            "can be used for the project ID if scanning a specific project."
        )

    def get_findings(self, json_output, test):
        return SnykApiImporter().get_findings(json_output, test)
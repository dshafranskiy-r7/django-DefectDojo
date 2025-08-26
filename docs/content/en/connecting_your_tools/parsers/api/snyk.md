---
title: "Snyk API Import"
toc_hide: true
---
All parsers which using API have common basic configuration step but with different values. Please, [read these steps](../) at first.

In `Tool Configuration`, select `Tool Type` to "Snyk" and `Authentication Type` "API Key".
Note the url must be in the format of `https://snyk.io/api/v1`
Paste your Snyk API token in the "API Key" field.
The tool will import vulnerability issues from Snyk projects.

In "Add API Scan Configuration"
-   `Service key 1` must
    be the Snyk Organization ID, which can be found in your Snyk dashboard under
    Settings > General.
-   `Service key 2` is optional and can be used to specify a specific Snyk Project ID.
    If not provided, DefectDojo will import findings from all projects in the organization.
    The Project ID can be found in the URL when viewing a specific project:
    `https://app.snyk.io/org/<org-id>/project/<project-id>`.

## Multiple Snyk API Configurations

In the import or re-import dialog you can select which `API Scan
Configuration` shall be used. If you do not choose
any, DefectDojo will use the `API Scan Configuration` of the Product if there is
only one defined or the Snyk `Tool Configuration` if there is only one.

## Bidirectional Synchronization

The Snyk API parser supports bidirectional synchronization between DefectDojo and Snyk:

- **DefectDojo to Snyk**: When findings are marked as false positives, mitigated, or risk accepted in DefectDojo, the corresponding Snyk issues are automatically ignored in Snyk.
- **Snyk to DefectDojo**: Changes to issue status in Snyk (ignored/resolved) are synchronized back to DefectDojo during subsequent imports.

## Supported Issue Types

The parser imports the following types of Snyk issues:
- **Vulnerabilities**: Security vulnerabilities in dependencies
- **License Issues**: License compliance violations
- **Code Quality**: Code quality and security issues from Snyk Code

## Data Mapping

- **Severity**: Snyk severities (critical/high/medium/low) are mapped to DefectDojo severities
- **CWE**: Common Weakness Enumeration identifiers are extracted when available
- **CVSS**: CVSS scores and vectors are imported when provided by Snyk
- **Components**: Package names and versions are tracked
- **References**: Direct links to Snyk issue pages are included

**Note**: The HTTPS certificate used by Snyk must be trusted by the DefectDojo instance.
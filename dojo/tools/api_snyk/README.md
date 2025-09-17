# Snyk API Parser for DefectDojo

This implementation provides a complete Snyk API integration for DefectDojo, enabling bidirectional synchronization between Snyk and DefectDojo.

## Features

### Core Functionality
- **API Import**: Import Snyk vulnerabilities directly via API
- **Bidirectional Sync**: Two-way synchronization between Snyk and DefectDojo
- **Organization/Project Support**: Scan entire organizations or specific projects
- **Issue Tracking**: Track Snyk issues with dedicated models

### Supported Data
- Vulnerability severity mapping (Critical/High/Medium/Low)
- CWE extraction and mapping
- Component name and version tracking
- CVSS score integration
- Issue URLs and references

## Configuration

### Tool Configuration
1. Create a new Tool Configuration in DefectDojo:
   - **Name**: Snyk API
   - **Tool Type**: Snyk
   - **Authentication Type**: API
   - **API Key**: Your Snyk API token
   - **URL**: `https://snyk.io/api/v1` (or your Snyk instance URL)

### Product API Scan Configuration
1. Create a Product API Scan Configuration:
   - **Service Key 1**: Snyk Organization ID (required)
   - **Service Key 2**: Snyk Project ID (optional, for project-specific scans)

## Usage

### Import Findings
1. Create a new test with scan type "Snyk API Import"
2. Select the appropriate API Scan Configuration
3. Run the import - no file upload required

### Bidirectional Sync
The parser automatically handles:
- **DefectDojo → Snyk**: Updates Snyk issue status when findings are modified
- **Snyk → DefectDojo**: Syncs status changes from Snyk back to DefectDojo

### Status Mapping
| DefectDojo Status | Snyk Action |
|------------------|-------------|
| False Positive   | Ignore (false-positive) |
| Mitigated        | Ignore (fixed) |
| Risk Accepted    | Ignore (wont-fix) |
| Active           | Unignore |

## API Methods

### Snyk API Client
- `get_organizations()` - List available organizations
- `get_projects(org_id)` - List projects in organization
- `get_issues(org_id, project_id=None)` - Get vulnerabilities
- `ignore_issue(org_id, issue_id, reason)` - Ignore vulnerability
- `unignore_issue(org_id, issue_id)` - Unignore vulnerability
- `test_connection()` - Verify API connectivity

## Models

### Snyk_Issue
Tracks Snyk issues for bidirectional sync:
- `key`: Snyk issue identifier
- `status`: Current issue status
- `type`: Issue type (vuln, license, etc.)

### Snyk_Issue_Transition
Audit trail for sync operations:
- `snyk_issue`: Related Snyk issue
- `finding_status`: DefectDojo finding status
- `snyk_status`: Snyk issue status
- `transitions`: Actions performed

## Testing

Unit tests are provided in:
- `unittests/tools/test_api_snyk_parser.py`
- `unittests/tools/test_api_snyk_importer.py`

Test data available in:
- `unittests/scans/api_snyk/`

## Error Handling

The parser includes comprehensive error handling for:
- API connection failures
- Authentication errors
- Missing configurations
- Invalid responses

Errors are logged and notifications are created for monitoring.
# Backward Sync from DefectDojo to Snyk Tool

This document explains how backward synchronization works in DefectDojo and how to implement it for Snyk, using the existing SonarQube implementation as reference.

## Overview

Backward sync allows DefectDojo to push finding status changes back to the original tool (like Snyk) to keep the tools in sync. When a finding status changes in DefectDojo (e.g., marked as false positive, mitigated, or risk accepted), these changes are propagated back to the source tool.

## Current Implementation: SonarQube Reference

DefectDojo already has a working backward sync implementation for SonarQube located in `dojo/tools/api_sonarqube/`. This serves as the blueprint for implementing Snyk backward sync.

### SonarQube Implementation Components

1. **Updater Class** (`dojo/tools/api_sonarqube/updater.py`):
   - `SonarQubeApiUpdater` class handles the backward sync logic
   - Maps DefectDojo finding statuses to SonarQube issue statuses
   - Defines state transitions between statuses
   - Handles API calls to update issues in SonarQube

2. **Models** (`dojo/models.py`):
   - `Sonarqube_Issue` - Links DefectDojo findings to SonarQube issues
   - `Sonarqube_Issue_Transition` - Tracks sync operations and status changes

3. **Tool Issue Updater** (`dojo/tools/tool_issue_updater.py`):
   - Central dispatcher that calls appropriate updater based on test type
   - Currently supports SonarQube API scans

## Triggering Backward Sync

### Automatic Triggers

Backward sync is automatically triggered when:

1. **Finding Status Changes**: Any change to finding status fields triggers sync via Django signals
   - Fields monitored: `active`, `verified`, `false_p`, `is_mitigated`, `mitigated`, `out_of_scope`, `risk_accepted`
   - Implemented in `dojo/finding/helper.py` using `pre_save_changed` signal
   - Calls `post_process_finding_save()` which includes `tool_issue_updater.async_tool_issue_update(finding)`

2. **Individual Finding Updates**: Any save operation on a finding object
   - Through UI forms (edit finding page)
   - Through API v2 endpoints (PUT/PATCH requests)

### Manual Triggers

1. **Bulk Update Operations**: Users can manually trigger sync for multiple findings
   - UI Location: Finding list pages with bulk action forms
   - Endpoints: `/finding/bulk` and `/product/{pid}/finding/bulk_product`
   - Action: Select findings and submit bulk update form

## UI Actions that Trigger Backward Sync

### 1. Individual Finding Updates

**UI Location**: Finding detail/edit pages
- Navigate to: `/finding/{finding_id}/edit`
- Actions that trigger sync:
  - Changing status (Active/Inactive)
  - Marking as False Positive
  - Marking as Mitigated
  - Accepting Risk
  - Verifying findings

**POST Request**: 
```
POST /finding/{finding_id}/edit
Content-Type: application/x-www-form-urlencoded

active=true&verified=true&false_p=false&is_mitigated=false&...
```

### 2. Bulk Finding Updates

**UI Location**: Finding list pages
- Navigate to: `/finding/` (all findings) or `/product/{pid}/finding/open` (product findings)
- Actions:
  1. Select multiple findings using checkboxes
  2. Scroll to bottom bulk update form
  3. Make status changes and submit

**POST Request**:
```
POST /finding/bulk
Content-Type: application/x-www-form-urlencoded

finding_to_update=123&finding_to_update=124&finding_to_update=125&
active=true&verified=true&false_p=false&...
```

### 3. Quick Actions

**UI Location**: Various finding list views
- Single-click actions for common status changes:
  - "Mark as False Positive"
  - "Accept Risk"
  - "Close Finding"
  - "Reopen Finding"

**POST Requests**:
```
POST /finding/{fid}/simple_risk_accept
POST /finding/{fid}/simple_risk_unaccept  
POST /finding/{fid}/close
POST /finding/{fid}/open
```

## API Endpoints that Trigger Backward Sync

### 1. API v2 Finding Endpoints

**Individual Finding Updates**:
```
PUT /api/v2/findings/{id}/
PATCH /api/v2/findings/{id}/
Content-Type: application/json

{
    "active": false,
    "verified": true,
    "false_p": true,
    "is_mitigated": false,
    "risk_accepted": true
}
```

**Bulk Operations** (if implemented):
```
PATCH /api/v2/findings/
Content-Type: application/json

{
    "findings": [123, 124, 125],
    "active": false,
    "false_p": true
}
```

## Implementation for Snyk Tool

To implement backward sync for Snyk, the following components need to be created:

### 1. Directory Structure

Create new directory: `dojo/tools/api_snyk/`

Required files:
- `__init__.py`
- `api_client.py` - Snyk API client for making API calls
- `updater.py` - Main updater logic (similar to SonarQube)
- `parser.py` - Import functionality from Snyk
- `importer.py` - Helper for import operations

### 2. Snyk Models

Add to `dojo/models.py`:

```python
class Snyk_Issue(models.Model):
    issue_id = models.CharField(max_length=200)
    issue_url = models.URLField(max_length=2000, null=True, blank=True)
    finding = models.OneToOneField(Finding, on_delete=models.CASCADE)

class Snyk_Issue_Transition(models.Model):
    snyk_issue = models.ForeignKey(Snyk_Issue, on_delete=models.CASCADE)
    finding_status = models.CharField(max_length=100)
    snyk_status = models.CharField(max_length=100)
    transitions = models.CharField(max_length=100)
    created = models.DateTimeField(auto_now_add=True)
```

### 3. Snyk API Client (`dojo/tools/api_snyk/api_client.py`)

```python
class SnykApiClient:
    def __init__(self, api_token, base_url="https://api.snyk.io"):
        self.api_token = api_token
        self.base_url = base_url
        
    def get_issue(self, issue_id):
        """Get issue details from Snyk API"""
        
    def update_issue_status(self, issue_id, status):
        """Update issue status in Snyk"""
        
    def ignore_issue(self, issue_id, reason):
        """Mark issue as ignored in Snyk"""
```

### 4. Snyk Updater (`dojo/tools/api_snyk/updater.py`)

```python
class SnykApiUpdater:
    # Status mapping from DefectDojo to Snyk
    @staticmethod
    def get_snyk_status_for(finding):
        if finding.false_p:
            return "ignored"  # Snyk's false positive equivalent
        elif finding.mitigated or finding.is_mitigated:
            return "resolved"
        elif finding.risk_accepted:
            return "ignored"  # Risk accepted maps to ignored
        elif finding.active:
            return "open"
        return None
        
    def update_snyk_finding(self, finding):
        """Main method to sync finding status to Snyk"""
        snyk_issue = finding.snyk_issue
        if not snyk_issue:
            return
            
        client = SnykApiClient(api_token=get_snyk_token())
        target_status = self.get_snyk_status_for(finding)
        
        # Update in Snyk via API
        client.update_issue_status(snyk_issue.issue_id, target_status)
        
        # Track the transition
        Snyk_Issue_Transition.objects.create(
            snyk_issue=snyk_issue,
            finding_status=finding.status(),
            snyk_status=target_status,
            transitions=f"DefectDojo -> {target_status}"
        )
```

### 5. Tool Issue Updater Integration

Update `dojo/tools/tool_issue_updater.py`:

```python
SCAN_SNYK_API = "Snyk API Import"  # Add this constant

def is_tool_issue_updater_needed(finding, *args, **kwargs):
    test_type = finding.test.test_type
    return test_type.name in [SCAN_SONARQUBE_API, SCAN_SNYK_API]

@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def tool_issue_updater(finding, *args, **kwargs):
    test_type = finding.test.test_type
    
    if test_type.name == SCAN_SONARQUBE_API:
        from dojo.tools.api_sonarqube.updater import SonarQubeApiUpdater
        SonarQubeApiUpdater().update_sonarqube_finding(finding)
    elif test_type.name == SCAN_SNYK_API:
        from dojo.tools.api_snyk.updater import SnykApiUpdater
        SnykApiUpdater().update_snyk_finding(finding)
```

### 6. Test Type Configuration

Create or configure a test type for "Snyk API Import" in DefectDojo admin:
- Name: "Snyk API Import" 
- Static tool: Yes
- Dynamic tool: No

## Status Mapping: DefectDojo to Snyk

| DefectDojo Status | DefectDojo Field | Snyk Status | Snyk Action |
|-------------------|------------------|-------------|-------------|
| Active | `active=True` | `open` | Reopen issue |
| Verified | `verified=True` | `open` | Keep as open |
| False Positive | `false_p=True` | `ignored` | Ignore with reason "false-positive" |
| Mitigated | `is_mitigated=True` | `resolved` | Mark as resolved |
| Risk Accepted | `risk_accepted=True` | `ignored` | Ignore with reason "wont-fix" |
| Inactive | `active=False` | `resolved` | Mark as resolved |

## Configuration Requirements

### 1. Snyk API Credentials

- API Token: Required for authentication with Snyk API
- Organization ID: Snyk organization where issues exist
- Project ID: Specific Snyk project (if applicable)

### 2. Finding Association

During import, findings must be linked to Snyk issues:
- Store Snyk issue ID in `Snyk_Issue` model
- Create relationship during initial import process
- Ensure `unique_id_from_tool` contains Snyk issue identifier

### 3. System Settings

Add configuration options:
- Enable/disable Snyk backward sync
- Snyk API credentials storage
- Sync behavior preferences

## Testing the Implementation

### 1. Manual Testing Steps

1. **Setup**: Configure Snyk API credentials and test type
2. **Import**: Import findings from Snyk to create linked issues
3. **Status Change**: Change finding status in DefectDojo UI
4. **Verify**: Check that corresponding issue in Snyk reflects the change
5. **Bulk Test**: Use bulk update to change multiple findings
6. **API Test**: Use API endpoints to change finding status

### 2. Expected Behavior

- Status changes in DefectDojo should reflect in Snyk within minutes
- Failed sync attempts should be logged for debugging
- Transition history should be maintained in `Snyk_Issue_Transition`
- Performance should not be significantly impacted by sync operations

## Limitations and Considerations

### 1. Snyk API Limitations

- Rate limiting: Snyk API has rate limits that may affect bulk operations
- Permissions: API token must have appropriate permissions to modify issues
- Issue state: Some Snyk issue states may not have direct DefectDojo equivalents

### 2. Error Handling

- Network failures during sync should be retried
- Invalid or missing Snyk issues should be handled gracefully
- Async operations should include proper error logging

### 3. Performance

- Large bulk operations may take time due to API rate limits
- Consider implementing batching for bulk sync operations
- Monitor Celery task queue for sync job performance

## Summary

Backward sync from DefectDojo to Snyk follows the same pattern as the existing SonarQube implementation. The key components are:

1. **API Client**: Handles communication with Snyk API
2. **Updater**: Maps DefectDojo statuses to Snyk and performs updates
3. **Models**: Track issue relationships and transition history
4. **Integration**: Hook into existing tool updater framework

The sync is triggered automatically by finding status changes and manually through bulk update operations, ensuring that DefectDojo and Snyk remain synchronized for effective vulnerability management.
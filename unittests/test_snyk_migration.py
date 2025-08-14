import unittest
from django_test_migrations.contrib.unittest_case import MigratorTestCase


class TestSnykMigration(MigratorTestCase):
    """Test that Snyk migration 0241 runs successfully and creates expected models."""
    
    migrate_from = ("dojo", "0240_jira_instance_password_help_text_fix")
    migrate_to = ("dojo", "0241_snyk_issue_finding_snyk_issue_snyk_issue_transition")

    def test_snyk_models_created(self):
        """Test that Snyk models are created after migration."""
        # Get the models from the new state after migration
        Snyk_Issue = self.new_state.apps.get_model("dojo", "Snyk_Issue")
        Snyk_Issue_Transition = self.new_state.apps.get_model("dojo", "Snyk_Issue_Transition")
        Finding = self.new_state.apps.get_model("dojo", "Finding")
        
        # Verify that the models exist and have the expected structure
        self.assertTrue(hasattr(Snyk_Issue, 'key'))
        self.assertTrue(hasattr(Snyk_Issue, 'status'))
        self.assertTrue(hasattr(Snyk_Issue, 'type'))
        
        self.assertTrue(hasattr(Snyk_Issue_Transition, 'snyk_issue'))
        self.assertTrue(hasattr(Snyk_Issue_Transition, 'created'))
        self.assertTrue(hasattr(Snyk_Issue_Transition, 'finding_status'))
        self.assertTrue(hasattr(Snyk_Issue_Transition, 'snyk_status'))
        self.assertTrue(hasattr(Snyk_Issue_Transition, 'transitions'))
        
        # Verify that Finding has the snyk_issue foreign key
        self.assertTrue(hasattr(Finding, 'snyk_issue'))
        
        # Test creating a Snyk_Issue instance
        snyk_issue = Snyk_Issue.objects.create(
            key="SNYK-TEST-123",
            status="Open",
            type="Vulnerability"
        )
        self.assertEqual(snyk_issue.key, "SNYK-TEST-123")
        self.assertEqual(snyk_issue.status, "Open")
        self.assertEqual(snyk_issue.type, "Vulnerability")
        
        # Test creating a Snyk_Issue_Transition instance
        transition = Snyk_Issue_Transition.objects.create(
            snyk_issue=snyk_issue,
            finding_status="Active",
            snyk_status="Open",
            transitions="created"
        )
        self.assertEqual(transition.snyk_issue, snyk_issue)
        self.assertEqual(transition.finding_status, "Active")
        self.assertEqual(transition.snyk_status, "Open")
        self.assertEqual(transition.transitions, "created")

    def test_models_not_present_before_migration(self):
        """Test that Snyk models don't exist before migration."""
        # Try to get the models from the old state before migration
        with self.assertRaises(LookupError):
            self.old_state.apps.get_model("dojo", "Snyk_Issue")
        
        with self.assertRaises(LookupError):
            self.old_state.apps.get_model("dojo", "Snyk_Issue_Transition")
        
        # Finding should exist but without snyk_issue field
        Finding = self.old_state.apps.get_model("dojo", "Finding")
        self.assertFalse(hasattr(Finding, 'snyk_issue'))
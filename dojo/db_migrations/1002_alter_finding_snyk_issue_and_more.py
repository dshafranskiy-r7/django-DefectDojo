import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '1001_snyk_issue_finding_snyk_issue_snyk_issue_transition'),
    ]

    operations = [
        migrations.AlterField(
            model_name='finding',
            name='snyk_issue',
            field=models.ForeignKey(blank=True, help_text='The Snyk issue associated with this finding.', null=True, on_delete=django.db.models.deletion.CASCADE, to='dojo.snyk_issue', verbose_name='Snyk issue'),
        ),
        migrations.AlterField(
            model_name='snyk_issue_transition',
            name='created',
            field=models.DateTimeField(auto_now_add=True),
        ),
    ]
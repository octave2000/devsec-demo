"""
Add avatar (ImageField) and document (FileField) to Profile.

Security notes
──────────────
• Both fields use UUID-based upload_to callables (see validators.py) so that
  stored filenames are never derived from user input — preventing path
  traversal and filename collision attacks.
• Both fields carry server-side validators (content-based, not just extension).
• null=True / blank=True so existing profiles are not broken.
"""

import mupenz_fulgence.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mupenz_fulgence', '0002_fix_profile_schema'),
    ]

    operations = [
        migrations.AddField(
            model_name='profile',
            name='avatar',
            field=models.ImageField(
                blank=True,
                help_text='Profile picture — JPEG, PNG, or WebP; max 2 MB.',
                null=True,
                upload_to=mupenz_fulgence.validators.avatar_upload_to,
                validators=[mupenz_fulgence.validators.validate_avatar],
            ),
        ),
        migrations.AddField(
            model_name='profile',
            name='document',
            field=models.FileField(
                blank=True,
                help_text='PDF document — max 5 MB.',
                null=True,
                upload_to=mupenz_fulgence.validators.document_upload_to,
                validators=[mupenz_fulgence.validators.validate_document],
            ),
        ),
    ]

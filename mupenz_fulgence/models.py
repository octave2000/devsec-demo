from django.contrib.auth.models import User
from django.db import models

from .validators import (
    avatar_upload_to,
    document_upload_to,
    validate_avatar,
    validate_document,
)


class Profile(models.Model):
    """
    Extends the built-in User model with additional personal information.
    Linked via OneToOneField so each User has exactly one Profile.

    File upload security
    ────────────────────
    avatar   — ImageField validated by Pillow (real image content check) plus
               an explicit size cap and extension whitelist.  The file is stored
               under a UUID-based randomised path to prevent path guessing and
               filename collision attacks.

    document — FileField validated by magic-byte inspection (PDF header check)
               plus size cap and extension whitelist.  Only .pdf files with a
               valid PDF signature are accepted.  Served exclusively through a
               Django view that enforces ownership checks, so the raw storage
               URL is never exposed publicly.
    """

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile',
    )
    bio        = models.TextField(blank=True, max_length=500)
    location   = models.CharField(max_length=100, blank=True)
    birth_date = models.DateField(null=True, blank=True)

    # ── Avatar ─────────────────────────────────────────────────────────────────
    # SECURITY: upload_to generates a UUID filename (see validators.py).
    # validate_avatar checks size, extension whitelist, and Pillow content.
    avatar = models.ImageField(
        upload_to=avatar_upload_to,
        null=True,
        blank=True,
        validators=[validate_avatar],
        help_text='Profile picture — JPEG, PNG, or WebP; max 2 MB.',
    )

    # ── Document ───────────────────────────────────────────────────────────────
    # SECURITY: upload_to generates a UUID filename (see validators.py).
    # validate_document checks size, extension whitelist, and PDF magic bytes.
    # NEVER serve this file via MEDIA_URL; use DocumentServeView instead.
    document = models.FileField(
        upload_to=document_upload_to,
        null=True,
        blank=True,
        validators=[validate_document],
        help_text='PDF document — max 5 MB.',
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name        = 'Profile'
        verbose_name_plural = 'Profiles'

    def __str__(self):
        return f'{self.user.username} — Profile'

    def get_display_name(self):
        """Return full name when available, otherwise fall back to username."""
        return self.user.get_full_name() or self.user.username

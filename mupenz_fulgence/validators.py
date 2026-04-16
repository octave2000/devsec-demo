"""
mupenz_fulgence/validators.py
─────────────────────────────
Server-side file validators for avatar and document uploads.

Security rationale
──────────────────
Client-provided metadata (filename, Content-Type header) CANNOT be trusted:
  • Attackers can rename any file to bypass extension checks.
  • Browsers derive Content-Type from the extension, not the file content.

We therefore perform content-based validation in addition to extension checks:

  Avatars:
    Pillow's Image.open() + verify() reads the actual file bytes and raises
    UnidentifiedImageError for any non-image content, including scripts or
    executables disguised as images (e.g. a PHP webshell named "photo.jpg").

  Documents:
    Magic-byte check — every valid PDF begins with the 5-byte ASCII sequence
    b'%PDF-'.  A renamed executable or HTML file will lack this header and
    is rejected unconditionally, regardless of its declared extension.

Both validators also enforce maximum file sizes to prevent denial-of-service
via excessively large uploads.

Upload-path helpers
───────────────────
avatar_upload_to / document_upload_to generate a randomised UUID filename
for every upload.  This prevents:
  • Directory traversal  (e.g. "../../etc/passwd" as a filename)
  • Filename collision / overwrite attacks
  • Information leakage (original filename is never stored publicly)
"""

import os
import uuid

from django.core.exceptions import ValidationError
from PIL import Image, UnidentifiedImageError

# ── Size limits ───────────────────────────────────────────────────────────────
AVATAR_MAX_BYTES   = 2 * 1024 * 1024   # 2 MB
DOCUMENT_MAX_BYTES = 5 * 1024 * 1024   # 5 MB

# ── Extension whitelists (fast first-pass filter; NOT the authoritative check)
ALLOWED_AVATAR_EXTENSIONS   = frozenset({'.jpg', '.jpeg', '.png', '.webp'})
ALLOWED_DOCUMENT_EXTENSIONS = frozenset({'.pdf'})

# ── PDF magic bytes ───────────────────────────────────────────────────────────
# Every valid PDF file starts with this 5-byte signature.
_PDF_MAGIC = b'%PDF-'


# ── Private helpers ───────────────────────────────────────────────────────────

def _safe_ext(filename: str) -> str:
    """Return the lowercased file extension from *filename*, or '' if absent."""
    _, ext = os.path.splitext(filename or '')
    return ext.lower()


# ── Upload-path callables ─────────────────────────────────────────────────────

def avatar_upload_to(instance, filename: str) -> str:
    """
    Generate a randomised storage path for an avatar upload.

    Path pattern: avatars/<user_pk>/<uuid4_hex><ext>

    Why UUID filenames?
      - Prevents guessing: the stored path is never the same as the original.
      - Prevents overwrite: two uploads with the same original name produce
        different storage keys.
      - Prevents path traversal: the original name is discarded entirely.
    """
    user_id = getattr(instance, 'user_id', None) or 'unknown'
    ext = _safe_ext(filename) or '.bin'
    return f'avatars/{user_id}/{uuid.uuid4().hex}{ext}'


def document_upload_to(instance, filename: str) -> str:
    """
    Generate a randomised storage path for a document upload.

    Path pattern: documents/<user_pk>/<uuid4_hex>.pdf
    """
    user_id = getattr(instance, 'user_id', None) or 'unknown'
    ext = _safe_ext(filename) or '.bin'
    return f'documents/{user_id}/{uuid.uuid4().hex}{ext}'


# ── Validators ────────────────────────────────────────────────────────────────

def validate_avatar(file) -> None:
    """
    Validate an uploaded avatar image.

    Security checks performed (all server-side — client data is not trusted):
      1. Size ≤ AVATAR_MAX_BYTES          → DoS / resource exhaustion prevention
      2. Extension in whitelist            → fast first-pass filter
      3. Pillow Image.open() + verify()   → definitive content-based check;
         any file that isn't a real image (script, binary, HTML) raises here
         regardless of its declared extension or Content-Type.

    Note: Django's forms.ImageField already calls Pillow for form-level uploads.
    Adding this validator on the model field ensures the check fires when files
    are set via the admin interface or programmatic ORM calls that bypass forms.
    """
    # 1. File size check
    if hasattr(file, 'size') and file.size > AVATAR_MAX_BYTES:
        limit_mb = AVATAR_MAX_BYTES // (1024 * 1024)
        raise ValidationError(
            f'Avatar file must not exceed {limit_mb} MB '
            f'(your file: {file.size // 1024} KB).'
        )

    # 2. Extension whitelist (defence-in-depth; Pillow is authoritative below)
    ext = _safe_ext(getattr(file, 'name', ''))
    if ext and ext not in ALLOWED_AVATAR_EXTENSIONS:
        raise ValidationError(
            f'File type "{ext}" is not allowed for avatars. '
            'Accepted formats: JPEG, PNG, WebP.'
        )

    # 3. Pillow content verification — the authoritative MIME check.
    #    Image.open() parses the file header; verify() reads the full content.
    #    A PHP/HTML/EXE file renamed to ".jpg" will raise UnidentifiedImageError.
    try:
        file.seek(0)
        img = Image.open(file)
        img.verify()
    except (UnidentifiedImageError, Exception) as exc:
        raise ValidationError(
            'The file does not appear to be a valid image. '
            'Please upload a JPEG, PNG, or WebP image.'
        ) from exc
    finally:
        # Always reset the file pointer so the storage backend can read
        # the full content after validation completes.
        try:
            file.seek(0)
        except Exception:
            pass


def validate_document(file) -> None:
    """
    Validate an uploaded PDF document.

    Security checks performed (all server-side):
      1. Size ≤ DOCUMENT_MAX_BYTES     → DoS / resource exhaustion prevention
      2. Extension == '.pdf'           → fast first-pass filter
      3. Magic-byte check (b'%PDF-')   → content verification; a renamed
         executable, script, or HTML file will lack the PDF header and is
         rejected regardless of its declared extension or Content-Type.
    """
    # 1. File size check
    if hasattr(file, 'size') and file.size > DOCUMENT_MAX_BYTES:
        limit_mb = DOCUMENT_MAX_BYTES // (1024 * 1024)
        raise ValidationError(
            f'Document file must not exceed {limit_mb} MB '
            f'(your file: {file.size // 1024} KB).'
        )

    # 2. Extension whitelist
    ext = _safe_ext(getattr(file, 'name', ''))
    if ext not in ALLOWED_DOCUMENT_EXTENSIONS:
        raise ValidationError(
            f'File type "{ext}" is not allowed. '
            'Only PDF documents (.pdf) are accepted.'
        )

    # 3. PDF magic-byte check — every valid PDF starts with b'%PDF-'
    try:
        file.seek(0)
        header = file.read(len(_PDF_MAGIC))
        if header != _PDF_MAGIC:
            raise ValidationError(
                'The file does not appear to be a valid PDF document. '
                'Please upload a PDF file.'
            )
    finally:
        try:
            file.seek(0)
        except Exception:
            pass

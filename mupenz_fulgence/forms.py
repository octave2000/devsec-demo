import re

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from .models import Profile
from .validators import (
    ALLOWED_AVATAR_EXTENSIONS,
    ALLOWED_DOCUMENT_EXTENSIONS,
    AVATAR_MAX_BYTES,
    DOCUMENT_MAX_BYTES,
    validate_avatar,
    validate_document,
)

# Matches any HTML tag: <tag>, </tag>, <tag attr="val"/>, etc.
# Requires a letter immediately after the optional closing slash so that plain
# math expressions like "a < b" or "x > y" do not trigger a false positive.
_HTML_TAG_RE = re.compile(r'</?[a-zA-Z][^>]*>')


def _reject_html(value: str, field_label: str) -> str:
    """
    Raise ValidationError when *value* contains an HTML tag.

    This is a defence-in-depth measure: Django's template engine auto-escapes
    all variables by default, so stored tags are never executed as HTML.
    However, keeping raw markup out of the database prevents confusion in
    admin interfaces, plain-text API consumers, and future template changes
    that might use |safe or format_html incorrectly.
    """
    if _HTML_TAG_RE.search(value):
        raise forms.ValidationError(
            f'{field_label} must not contain HTML tags.'
        )
    return value


class RegistrationForm(UserCreationForm):
    """
    Extended registration form that collects email (required),
    first name, and last name in addition to the standard fields.
    """
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'autocomplete': 'email',
            'class': 'form-control',
        }),
        help_text='Required. A confirmation may be sent to this address.',
    )
    first_name = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={
            'autocomplete': 'given-name',
            'class': 'form-control',
        }),
    )
    last_name = forms.CharField(
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={
            'autocomplete': 'family-name',
            'class': 'form-control',
        }),
    )

    class Meta:
        model = User
        fields = (
            'username',
            'first_name',
            'last_name',
            'email',
            'password1',
            'password2',
        )
        widgets = {
            'username': forms.TextInput(attrs={
                'autocomplete': 'username',
                'class': 'form-control',
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Apply Bootstrap class to password fields rendered by UserCreationForm
        self.fields['password1'].widget.attrs.update({'class': 'form-control'})
        self.fields['password2'].widget.attrs.update({'class': 'form-control'})

    def clean_email(self):
        email = self.cleaned_data.get('email', '').lower()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError(
                'An account with this email address already exists.'
            )
        return email

    # XSS defence-in-depth: reject HTML markup in name fields so raw tags
    # never reach the database, protecting admin UIs and any future context
    # that might render values without auto-escaping.
    def clean_first_name(self):
        return _reject_html(self.cleaned_data.get('first_name', ''), 'First name')

    def clean_last_name(self):
        return _reject_html(self.cleaned_data.get('last_name', ''), 'Last name')

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.cleaned_data['email']
        user.first_name = self.cleaned_data.get('first_name', '')
        user.last_name = self.cleaned_data.get('last_name', '')
        if commit:
            user.save()
        return user


class ProfileUpdateForm(forms.ModelForm):
    """
    Updates both User (first_name, last_name, email) and
    Profile (bio, location, birth_date) in a single form submission.
    """
    first_name = forms.CharField(
        max_length=30,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
    )
    last_name = forms.CharField(
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'form-control'}),
    )

    class Meta:
        model = Profile
        fields = ('bio', 'location', 'birth_date')
        widgets = {
            'bio': forms.Textarea(attrs={
                'rows': 4,
                'class': 'form-control',
                'placeholder': 'A short bio about yourself…',
            }),
            'location': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'City, Country',
            }),
            'birth_date': forms.DateInput(attrs={
                'type': 'date',
                'class': 'form-control',
            }),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Pre-populate User fields from the related User instance
        if self.instance and hasattr(self.instance, 'user'):
            user = self.instance.user
            self.fields['first_name'].initial = user.first_name
            self.fields['last_name'].initial = user.last_name
            self.fields['email'].initial = user.email

    def clean_email(self):
        email = self.cleaned_data.get('email', '').lower()
        current_user_pk = self.instance.user.pk
        if User.objects.filter(email__iexact=email).exclude(pk=current_user_pk).exists():
            raise forms.ValidationError(
                'This email address is already in use by another account.'
            )
        return email

    # XSS defence-in-depth: wire up _reject_html for every user-controlled
    # text field so that HTML markup is rejected at validation time and never
    # stored in the database.  Django's template auto-escaping is the primary
    # protection; these validators are a second line of defence that keeps raw
    # markup out of the database entirely.
    def clean_first_name(self):
        return _reject_html(self.cleaned_data.get('first_name', ''), 'First name')

    def clean_last_name(self):
        return _reject_html(self.cleaned_data.get('last_name', ''), 'Last name')

    def clean_bio(self):
        return _reject_html(self.cleaned_data.get('bio', ''), 'Bio')

    def clean_location(self):
        return _reject_html(self.cleaned_data.get('location', ''), 'Location')

    def save(self, commit=True):
        profile = super().save(commit=False)
        if commit:
            # Persist User-level fields alongside the Profile
            user = profile.user
            user.first_name = self.cleaned_data.get('first_name', '')
            user.last_name = self.cleaned_data.get('last_name', '')
            user.email = self.cleaned_data.get('email', '')
            user.save()
            profile.save()
        return profile


# ── File upload forms ──────────────────────────────────────────────────────────

class AvatarUploadForm(forms.ModelForm):
    """
    Handles secure avatar uploads.

    Security layers
    ───────────────
    1. forms.ImageField — Django's built-in field calls Pillow to verify that
       the uploaded file is a real image (content-based, not just extension).
    2. clean_avatar()   — additional size cap and extension whitelist,
       plus an explicit call to validate_avatar() which also runs the Pillow
       check at the model-validator level (defence-in-depth).

    enctype="multipart/form-data" must be set on the HTML <form> tag.
    """

    avatar = forms.ImageField(
        label='Profile Picture',
        help_text=(
            f'Upload a JPEG, PNG, or WebP image. '
            f'Maximum size: {AVATAR_MAX_BYTES // (1024 * 1024)} MB.'
        ),
        widget=forms.ClearableFileInput(attrs={'class': 'form-control', 'accept': 'image/*'}),
    )

    class Meta:
        model  = Profile
        fields = ('avatar',)

    def clean_avatar(self):
        file = self.cleaned_data.get('avatar')
        if file:
            # Delegate to the centralised validator in validators.py.
            # This runs the size check, extension whitelist, and Pillow verify().
            validate_avatar(file)
        return file


class DocumentUploadForm(forms.ModelForm):
    """
    Handles secure PDF document uploads.

    Security layers
    ───────────────
    1. forms.FileField  — basic file handling; does NOT validate content.
    2. clean_document() — size cap, extension whitelist (.pdf only), and
       magic-byte verification (file must start with b'%PDF-').
       A PHP script renamed to 'resume.pdf' will be rejected at step 3.

    Access control: documents are served ONLY via DocumentServeView, which
    enforces ownership checks.  The raw storage path is never exposed.

    enctype="multipart/form-data" must be set on the HTML <form> tag.
    """

    document = forms.FileField(
        label='PDF Document',
        help_text=(
            f'Upload a PDF document. '
            f'Maximum size: {DOCUMENT_MAX_BYTES // (1024 * 1024)} MB.'
        ),
        widget=forms.ClearableFileInput(attrs={'class': 'form-control', 'accept': '.pdf'}),
    )

    class Meta:
        model  = Profile
        fields = ('document',)

    def clean_document(self):
        file = self.cleaned_data.get('document')
        if file:
            # Delegate to the centralised validator in validators.py.
            # This runs: size check → extension whitelist → PDF magic bytes.
            validate_document(file)
        return file

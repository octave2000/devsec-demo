import re

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from .models import Profile

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

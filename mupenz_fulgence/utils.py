"""
mupenz_fulgence.utils
~~~~~~~~~~~~~~~~~~~~~
Shared security utilities for the User Authentication Service.
"""
from django.urls import reverse_lazy
from django.utils.http import url_has_allowed_host_and_scheme

#: Default landing page used when a redirect target fails validation.
_SAFE_FALLBACK = reverse_lazy('mupenz_fulgence:dashboard')


def safe_redirect_url(request, url, fallback=None):
    """
    Return *url* if it is safe to redirect to; otherwise return *fallback*.

    A URL is considered safe when:
      - It is a relative path that has no host component (e.g. '/auth/profile/')
      - OR its scheme and host match the current request's allowed hosts

    Blocked patterns (open-redirect attack vectors):
      - Full external HTTP/HTTPS URLs:  http://evil.com/  or  https://evil.com/
      - Protocol-relative URLs:         //evil.com/
      - JavaScript pseudo-URLs:         javascript:alert(1)
      - Data URIs:                       data:text/html,...

    Rationale
    ---------
    Django's built-in ``LoginView`` and ``LogoutView`` already call
    ``url_has_allowed_host_and_scheme`` internally via ``RedirectURLMixin``.
    This utility exposes the same check as a named, importable function so
    that any future custom view that needs to redirect based on user input can
    apply the exact same validation rather than rolling its own.

    Parameters
    ----------
    request  : HttpRequest
        Used to determine the allowed host and whether HTTPS is required.
    url      : str
        Candidate redirect target (typically from request.GET or request.POST).
    fallback : str | None
        Returned when *url* is deemed unsafe.  Defaults to the dashboard URL.

    Examples
    --------
    # In a custom view that respects a "next" query parameter:
    destination = request.GET.get('next', '')
    return redirect(safe_redirect_url(request, destination))

    # With an explicit fallback:
    safe = safe_redirect_url(request, raw_url, fallback='/auth/login/')
    """
    if fallback is None:
        fallback = str(_SAFE_FALLBACK)
    is_safe = url_has_allowed_host_and_scheme(
        url=url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    )
    return url if is_safe else fallback

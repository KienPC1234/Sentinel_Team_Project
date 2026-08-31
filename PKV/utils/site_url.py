import threading
from django.conf import settings

# Thread-local storage to hold the current site URL for each request independently
_thread_locals = threading.local()

def set_current_site_url(url):
    """Sets the current request's base URL (e.g., https://fairspace.com)."""
    _thread_locals.site_url = url.rstrip('/')

def get_site_url():
    """Gets the site URL from current request context, or falls back to settings."""
    # Try to get the dynamic URL from thread locals first
    dynamic_url = getattr(_thread_locals, 'site_url', None)
    if dynamic_url:
        return dynamic_url
    
    # Fallback to a setting if defined, otherwise use a generic default
    return getattr(settings, 'DEFAULT_SITE_URL', 'https://cs.fptoj.com')

class DynamicSiteURL:
    """A proxy class that behaves like a string but returns the current site URL dynamically."""
    def __str__(self):
        return get_site_url()
    
    def __repr__(self):
        return str(self)
    
    def __add__(self, other):
        return str(self) + str(other)
    
    def __radd__(self, other):
        return str(other) + str(self)
    
    def rstrip(self, chars=None):
        return str(self).rstrip(chars)
    
    def lstrip(self, chars=None):
        return str(self).lstrip(chars)
    
    def strip(self, chars=None):
        return str(self).strip(chars)

    def lower(self):
        return str(self).lower()

    def upper(self):
        return str(self).upper()
    
    def __eq__(self, other):
        return str(self) == str(other)

    def __hash__(self):
        return hash(str(self))

    def __len__(self):
        return len(str(self))
    
    def __getattr__(self, name):
        # Fallback for other string methods
        return getattr(str(self), name)

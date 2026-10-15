from drf_spectacular.extensions import OpenApiAuthenticationExtension
from api.utils.authentication import CsrfExemptSessionAuthentication
from api.core.authentication import APIKeyAuthentication

class CsrfExemptSessionAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = CsrfExemptSessionAuthentication
    name = 'CsrfExemptSessionAuthentication'

    def get_security_definition(self, auto_schema):
        return {
            'type': 'apiKey',
            'in': 'cookie',
            'name': 'sessionid',
        }

class APIKeyAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = APIKeyAuthentication
    name = 'apiKeyAuth'

    def get_security_definition(self, auto_schema):
        return {
            'type': 'apiKey',
            'in': 'header',
            'name': 'X-API-Key',
            'description': 'ShieldCall VN Personal API Key (Format: sc_live_...)',
        }

def preprocessing_filter_spec(endpoints):
    """
    Preprocessing hook for DRF Spectacular.
    Only includes canonical v1 API endpoints (/api/v1/...) in the generated schema.
    """
    return [
        (path, path_regex, method, callback)
        for (path, path_regex, method, callback) in endpoints
        if path.startswith('/api/v1/')
    ]


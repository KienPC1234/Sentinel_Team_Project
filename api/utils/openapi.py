from drf_spectacular.extensions import OpenApiAuthenticationExtension
from api.utils.authentication import CsrfExemptSessionAuthentication

class CsrfExemptSessionAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = CsrfExemptSessionAuthentication
    name = 'CsrfExemptSessionAuthentication'

    def get_security_definition(self, auto_schema):
        return {
            'type': 'apiKey',
            'in': 'cookie',
            'name': 'sessionid',
        }

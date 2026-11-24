from drf_spectacular.extensions import OpenApiAuthenticationExtension
from drf_spectacular.openapi import AutoSchema
from drf_spectacular.plumbing import build_serializer_context
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer
from rest_framework.views import APIView

from api.core.authentication import APIKeyAuthentication


class FreeFormObjectSerializer(Serializer):
    """Named placeholder so free-form endpoints keep a stable schema component."""


class LenientAutoSchema(AutoSchema):
    """Fallback for legacy APIViews without serializer metadata.

    Most views in this project return hand-built dicts. Instead of omitting them
    from the schema (the drf-spectacular default), document them as free-form
    objects so generated clients still see the endpoint and its method.
    """

    def _get_serializer(self):
        view = self.view
        if (
            isinstance(view, APIView)
            and not isinstance(view, GenericAPIView)
            and not callable(getattr(view, 'get_serializer', None))
            and not callable(getattr(view, 'get_serializer_class', None))
            and not hasattr(view, 'serializer_class')
        ):
            return FreeFormObjectSerializer(context=build_serializer_context(view))
        return super()._get_serializer()


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


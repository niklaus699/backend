from __future__ import annotations

from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.tokens import AccessToken

from apps.tenants.context import clear_current_tenant, set_current_tenant


PUBLIC_PATH_PREFIXES = (
    "/api/auth/",
    "/api/v1/health/",
    "/admin/",
)


class TenantMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        tenant_id = None
        if not request.path.startswith(PUBLIC_PATH_PREFIXES):
            tenant_id = self._extract_tenant_id_from_jwt(request)

        try:
            if tenant_id:
                set_current_tenant(tenant_id)
            else:
                clear_current_tenant()
            return self.get_response(request)
        finally:
            clear_current_tenant()

    def _extract_tenant_id_from_jwt(self, request) -> str | None:
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth_header.startswith("Bearer "):
            return None

        token_str = auth_header[7:].strip()
        if not token_str:
            return None

        try:
            token = AccessToken(token_str)
        except InvalidToken:
            return None
        except Exception:
            return None

        tenant_id = token.get("organization_id")
        return str(tenant_id) if tenant_id else None

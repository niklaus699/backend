from django.db import connection


class TenantMiddleware:
    """
    Reads the organization_id from the authenticated JWT payload
    and sets it as a Postgres session variable before the view runs.

    Every subsequent query in this request will be filtered by RLS
    using this session variable — no ORM filter needed.

    IMPORTANT: This must run AFTER the JWT authentication middleware
    that populates request.user / request.auth.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        tenant_id = self._extract_tenant_id(request)

        if tenant_id:
            with connection.cursor() as cursor:
                # Use %s parameterization — never f-string a SQL value
                cursor.execute(
                    "SELECT set_config('app.current_tenant_id', %s, true)",
                    [str(tenant_id)]
                )
                # The 'true' flag means this setting is transaction-scoped,
                # which is correct — it resets after the request completes.

        response = self.get_response(request)
        return response

    def _extract_tenant_id(self, request) -> str | None:
        """
        Pull the organization_id from the JWT payload.
        djangorestframework-simplejwt stores the decoded token on request.auth.
        We put organization_id in the token at login time (see serializers.py).
        """
        if hasattr(request, 'auth') and request.auth is not None:
            return request.auth.get('organization_id')
        return None
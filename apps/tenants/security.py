from __future__ import annotations

from collections.abc import Iterable

from django.conf import settings


class ContentSecurityPolicyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        policy = getattr(settings, "CONTENT_SECURITY_POLICY", None)

        if policy and "Content-Security-Policy" not in response:
            response["Content-Security-Policy"] = self._render_policy(policy)

        return response

    def _render_policy(self, policy: dict[str, Iterable[str] | str]) -> str:
        rendered_directives: list[str] = []

        for directive, value in policy.items():
            if isinstance(value, str):
                rendered_value = value
            else:
                rendered_value = " ".join(value)
            rendered_directives.append(f"{directive} {rendered_value}")

        return "; ".join(rendered_directives)

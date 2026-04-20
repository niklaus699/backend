from __future__ import annotations

from contextlib import contextmanager
from uuid import UUID

from django.db import connection


TENANT_SETTING = "app.current_tenant_id"


def set_current_tenant(tenant_id: str | UUID) -> None:
    tenant_value = str(tenant_id)
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT set_config(%s, %s, false)",
            [TENANT_SETTING, tenant_value],
        )
        cursor.execute("SELECT current_setting(%s, true)", [TENANT_SETTING])
        current_value = cursor.fetchone()[0]

    if current_value != tenant_value:
        raise RuntimeError("Failed to set tenant context for the current request")


def clear_current_tenant() -> None:
    with connection.cursor() as cursor:
        cursor.execute(f"RESET {TENANT_SETTING}")


@contextmanager
def tenant_context(tenant_id: str | UUID):
    set_current_tenant(tenant_id)
    try:
        yield
    finally:
        clear_current_tenant()

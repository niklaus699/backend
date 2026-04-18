from rest_framework.views import exception_handler
from rest_framework.exceptions import NotFound
from django.core.exceptions import ObjectDoesNotExist


def sentinel_exception_handler(exc, context):
    """
    When RLS silently filters a row and the ORM raises DoesNotExist,
    return a clean 404 rather than leaking a 403 that hints the object
    exists in a different tenant's namespace.
    """
    if isinstance(exc, ObjectDoesNotExist):
        exc = NotFound()
    return exception_handler(exc, context)
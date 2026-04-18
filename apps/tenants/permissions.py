from rest_framework.permissions import BasePermission


class IsAnalystOrAbove(BasePermission):
    """Viewers can read. Analysts and above can read."""
    ALLOWED_ROLES = {'analyst', 'admin', 'owner'}

    def has_permission(self, request, view):
        return (
            request.auth is not None
            and request.auth.get('role') in self.ALLOWED_ROLES
        )


class IsAdminOrAbove(BasePermission):
    """Only admins and owners can mutate resources."""
    ALLOWED_ROLES = {'admin', 'owner'}

    def has_permission(self, request, view):
        return (
            request.auth is not None
            and request.auth.get('role') in self.ALLOWED_ROLES
        )


class IsOwner(BasePermission):
    """Organization settings, billing — owners only."""
    def has_permission(self, request, view):
        return (
            request.auth is not None
            and request.auth.get('role') == 'owner'
        )


class ReadOnly(BasePermission):
    SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS')

    def has_permission(self, request, view):
        return request.method in self.SAFE_METHODS
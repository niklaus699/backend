from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import serializers
from django.contrib.auth.hashers import check_password

from apps.tenants.models import User, Organization


class SentinelTokenObtainSerializer(TokenObtainPairSerializer):
    """
    Custom JWT serializer that:
    1. Authenticates against our User model (not Django's auth.User)
    2. Injects organization_id and role into the token payload

    The organization_id in the token is what TenantMiddleware reads
    to set the Postgres session variable before each request.
    """
    # Override the default fields — we auth by email, not username
    username_field = 'email'
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs['email'].lower().strip()
        password = attrs['password']

        try:
            user = User.objects.select_related('organization').get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError('Invalid credentials.')

        if not check_password(password, user.password_hash):
            raise serializers.ValidationError('Invalid credentials.')

        if not user.organization.is_active:
            raise serializers.ValidationError('Organization account is suspended.')

        # Build token pair with custom claims
        refresh = RefreshToken.for_user(user)
        self._inject_claims(refresh, user)

        from django.utils import timezone
        User.objects.filter(id=user.id).update(last_login=timezone.now())

        return {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': {
                'id': str(user.id),
                'email': user.email,
                'role': user.role,
                'organization': {
                    'id': str(user.organization.id),
                    'name': user.organization.name,
                    'slug': user.organization.slug,
                    'plan_tier': user.organization.plan_tier,
                },
            },
        }

    @staticmethod
    def _inject_claims(refresh: RefreshToken, user: User):
        """
        These claims are available on both access and refresh tokens.
        TenantMiddleware reads 'organization_id' from the access token.
        """
        claims = {
            'organization_id': str(user.organization.id),
            'organization_slug': user.organization.slug,
            'role': user.role,
            'email': user.email,
        }
        for key, value in claims.items():
            refresh[key] = value
            refresh.access_token[key] = value
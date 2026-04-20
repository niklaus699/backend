from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import serializers
from django.contrib.auth import password_validation
from django.db import transaction
from django.utils.text import slugify

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

        if not user.check_password(password):
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

class RegisterSerializer(serializers.Serializer):
    # Organization fields
    organization_name = serializers.CharField(max_length=255)

    # User fields
    email    = serializers.EmailField()
    password = serializers.CharField(min_length=8, write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate_email(self, value):
        value = User.objects.normalize_email(value).lower().strip()
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                'An account with this email already exists.'
            )
        return value

    def validate_organization_name(self, value):
        value = value.strip()
        slug = slugify(value)
        if Organization.objects.filter(slug=slug).exists():
            raise serializers.ValidationError(
                'An organization with this name already exists.'
            )
        return value

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({
                'confirm_password': 'Passwords do not match.'
            })

        password_validation.validate_password(attrs['password'])
        return attrs

    @transaction.atomic
    def create(self, validated_data):
        """
        Create the Organization and its first User (owner) atomically.
        If either insert fails, both roll back — no orphaned orgs or users.
        """
        org = Organization.objects.create(
            name=validated_data['organization_name'],
            slug=slugify(validated_data['organization_name']),
            plan_tier=Organization.PlanTier.FREE,
            is_active=True,
        )

        user = User.objects.create_user(
            organization=org,
            email=validated_data['email'],
            password=validated_data['password'],
            role=User.Role.OWNER,  # First user is always the org owner
        )

        return org, user

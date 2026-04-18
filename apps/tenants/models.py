import uuid
from django.db import models


class Organization(models.Model):
    """
    The root tenant object. Every other model traces back here.
    The 'slug' is used in JWT claims and RLS policy lookups.
    """
    class PlanTier(models.TextChoices):
        FREE = 'free', 'Free'
        PRO = 'pro', 'Pro'
        ENTERPRISE = 'enterprise', 'Enterprise'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    slug = models.SlugField(unique=True)
    plan_tier = models.CharField(
        max_length=20,
        choices=PlanTier.choices,
        default=PlanTier.FREE
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'tenants_organization'

    def __str__(self):
        return self.name


class User(models.Model):
    """
    Deliberately not using AbstractUser — we don't need Django's auth
    session machinery. JWT handles auth; this is just a profile record.
    In production you'd inherit AbstractBaseUser for password hashing.
    """
    class Role(models.TextChoices):
        OWNER = 'owner', 'Owner'
        ADMIN = 'admin', 'Admin'
        ANALYST = 'analyst', 'Analyst'
        VIEWER = 'viewer', 'Viewer'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='members'
    )
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.VIEWER)
    password_hash = models.CharField(max_length=255, null=True)
    last_login = models.DateTimeField(null=True, blank=True)
    # Inside your User model
    @property
    def is_active(self):
        return True  # Or your logic

    @property
    def pk(self):
        return self.id
    
    @property
    def is_authenticated(self):
        return True
    class Meta:
        db_table = 'tenants_user'
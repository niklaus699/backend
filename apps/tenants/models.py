import uuid
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
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


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email: str, password: str | None, **extra_fields):
        if not email:
            raise ValueError("Users must have an email address")

        email = self.normalize_email(email).lower()
        user = self.model(email=email, **extra_fields)

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save(using=self._db)
        return user

    def create_user(self, email: str, password: str | None = None, **extra_fields):
        extra_fields.setdefault("role", "viewer")
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email: str, password: str, **extra_fields):
        extra_fields.setdefault("role", "owner")
        return self._create_user(email, password, **extra_fields)


class User(AbstractBaseUser):
    """
    Lightweight custom user model for JWT-based auth.
    We keep the existing database column name for backwards compatibility,
    while using Django's built-in password helpers through AbstractBaseUser.
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
    password = models.CharField(max_length=255, db_column='password_hash')
    REQUIRED_FIELDS = []
    USERNAME_FIELD = 'email'
    objects = UserManager()

    @property
    def is_active(self):
        if self.organization_id:
            return self.organization.is_active
        return True

    @property
    def is_staff(self):
        return self.role in {self.Role.OWNER, self.Role.ADMIN}

    def save(self, *args, **kwargs):
        self.email = self.__class__.objects.normalize_email(self.email).lower()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.email

    class Meta:
        db_table = 'tenants_user'

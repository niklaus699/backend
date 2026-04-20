from django.conf import settings
from django.db import connection
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

from redis import Redis

from apps.tenants.serializers import (
    SentinelTokenObtainSerializer, RegisterSerializer)


class LoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class = SentinelTokenObtainSerializer
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'login'

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data)
    

class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'login'

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        org, user = serializer.save()

        # Issue tokens immediately — no separate login step needed
        refresh = RefreshToken.for_user(user)
        SentinelTokenObtainSerializer._inject_claims(refresh, user)

        return Response(
            {
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'role': user.role,
                    'organization': {
                        'id': str(org.id),
                        'name': org.name,
                        'slug': org.slug,
                        'plan_tier': org.plan_tier,
                    },
                },
            },
            status=status.HTTP_201_CREATED,
        )


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    checks: dict[str, str] = {}
    status_code = status.HTTP_200_OK

    try:
        connection.ensure_connection()
        checks['database'] = 'ok'
    except Exception as exc:
        checks['database'] = f'error: {exc}'
        status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    try:
        Redis.from_url(settings.CELERY_BROKER_URL).ping()
        checks['redis'] = 'ok'
    except Exception as exc:
        checks['redis'] = f'error: {exc}'
        status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return Response(
        {
            'status': 'healthy' if status_code == status.HTTP_200_OK else 'unhealthy',
            'checks': checks,
        },
        status=status_code,
    )

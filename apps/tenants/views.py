from django.shortcuts import render

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import TokenRefreshView

from apps.tenants.serializers import SentinelTokenObtainSerializer


class LoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class = SentinelTokenObtainSerializer

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data)
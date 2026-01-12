from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from .serializers import (
    SignupSerializer,
    LoginSerializer,
    UserSerializer,
    ProfileUpdateSerializer,
)

User = get_user_model()


REFRESH_COOKIE_NAME = "refresh_token"
REFRESH_COOKIE_PATH = "/api/auth/"  # restrict cookie to auth endpoints


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=refresh_token,
        httponly=True,
        secure=getattr(settings, "COOKIE_SECURE", False),
        samesite=getattr(settings, "COOKIE_SAMESITE", "Lax"),
        path=REFRESH_COOKIE_PATH,
        max_age=7 * 24 * 60 * 60,  # 7 days
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=REFRESH_COOKIE_NAME, path=REFRESH_COOKIE_PATH)


class SignupView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({"user": UserSerializer(user).data}, status=status.HTTP_201_CREATED)


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        identifier = serializer.validated_data["identifier"]
        password = serializer.validated_data["password"]

        # allow username OR email login
        user_obj = None
        if "@" in identifier:
            user_obj = User.objects.filter(email__iexact=identifier).first()
        else:
            user_obj = User.objects.filter(username__iexact=identifier).first()

        if not user_obj:
            return Response({"detail": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

        user = authenticate(username=user_obj.username, password=password)
        if not user:
            return Response({"detail": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED)

        token_serializer = TokenObtainPairSerializer(data={"username": user.username, "password": password})
        token_serializer.is_valid(raise_exception=True)

        refresh = token_serializer.validated_data["refresh"]
        access = token_serializer.validated_data["access"]

        resp = Response(
            {"access": access, "user": UserSerializer(user).data},
            status=status.HTTP_200_OK,
        )
        _set_refresh_cookie(resp, refresh)
        return resp


class RefreshView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_from_cookie = request.COOKIES.get(REFRESH_COOKIE_NAME)
        if not refresh_from_cookie:
            return Response({"detail": "Refresh token missing."}, status=status.HTTP_401_UNAUTHORIZED)

        refresh_serializer = TokenRefreshSerializer(data={"refresh": refresh_from_cookie})
        refresh_serializer.is_valid(raise_exception=True)

        access = refresh_serializer.validated_data["access"]
        new_refresh = refresh_serializer.validated_data.get("refresh")  # present if rotation enabled

        resp = Response({"access": access}, status=status.HTTP_200_OK)
        if new_refresh:
            _set_refresh_cookie(resp, new_refresh)
        return resp


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_from_cookie = request.COOKIES.get(REFRESH_COOKIE_NAME)

        # Clear cookie always
        resp = Response({"detail": "Logged out."}, status=status.HTTP_200_OK)
        _clear_refresh_cookie(resp)

        if refresh_from_cookie:
            try:
                token = RefreshToken(refresh_from_cookie)
                token.blacklist()
            except Exception:
                # token already invalid/expired; still consider logged out
                pass

        return resp


class MeView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def get(self, request):
        return Response(UserSerializer(request.user).data, status=status.HTTP_200_OK)

    def patch(self, request):
        serializer = ProfileUpdateSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(UserSerializer(user).data, status=status.HTTP_200_OK)

    def put(self, request):
        serializer = ProfileUpdateSerializer(request.user, data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(UserSerializer(user).data, status=status.HTTP_200_OK)

    def delete(self, request):
        request.user.delete()
        resp = Response({"detail": "User deleted."}, status=status.HTTP_200_OK)
        _clear_refresh_cookie(resp)
        return resp

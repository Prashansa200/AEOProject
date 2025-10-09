from rest_framework.generics import GenericAPIView, RetrieveUpdateAPIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from rest_framework import generics,permissions,mixins
from rest_framework.exceptions import PermissionDenied
from django.conf import settings
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.contrib.auth import get_user_model
from .models import CustomUser, UserOTP,Profile,PasswordResetOTP
from .serializers import (
    SignupSerializer, LoginSerializer, OTPVerifySerializer,VerifyChangePasswordOTPSerializer,
    ForgotPasswordSerializer, ResetPasswordSerializer, ProfileSerializer,ChangePasswordRequestSerializer,ProfResetPasswordSerializer,ProfilePhotoSerializer
)
import random

User = get_user_model()
verification_codes = {}
verification_otp = {}


# ---------------------------
# Signup View (Regular Users)
# ---------------------------
class SignupView(GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = SignupSerializer

    def post(self, request):
        email = request.data.get("email")  # assuming user signs up with email
        if CustomUser.objects.filter(email=email).exists():
            return Response(
                {"message": "User already exists"},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "User registered successfully"},
                status=status.HTTP_201_CREATED
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ---------------------------
# Login View (Regular Users)
# ---------------------------
class LoginView(GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({"error": "Invalid email or password"}, status=status.HTTP_400_BAD_REQUEST)

        # Prevent admin users from using this login
        if user.is_staff or user.is_superuser:
            return Response({"error": "Admins cannot login via user portal"}, status=status.HTTP_403_FORBIDDEN)

        if not user.check_password(password):
            return Response({"error": "Invalid email or password"}, status=status.HTTP_400_BAD_REQUEST)

        # Generate OTP for regular user
        otp_code = UserOTP.generate_otp()
        UserOTP.objects.create(user=user, otp=otp_code)

        # Send OTP to email
        send_mail(
            subject="Your Login OTP",
            message=f"Your OTP code is {otp_code}",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
        )
        verify_otp = request.build_absolute_uri(reverse('verify-otp'))
        return Response({"message": "OTP sent to your registered email.",
                         "user_id": user.id,
                         "Next":verify_otp
                         }, status=status.HTTP_200_OK)

# ---------------------------
# OTP Verification
# ---------------------------
class OTPVerifyView(GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = OTPVerifySerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        otp_input = serializer.validated_data['otp']

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_400_BAD_REQUEST)

        if user.is_staff or user.is_superuser:
            return Response({"error": "Admins cannot use OTP login"}, status=status.HTTP_403_FORBIDDEN)

        try:
            user_otp = UserOTP.objects.filter(user=user, is_verified=False).latest('created_at')
        except UserOTP.DoesNotExist:
            return Response({"error": "OTP not found"}, status=status.HTTP_400_BAD_REQUEST)

        if user_otp.is_expired():
            return Response({"error": "OTP expired"}, status=status.HTTP_400_BAD_REQUEST)

        if str(user_otp.otp) != str(otp_input):
            return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

        user_otp.is_verified = True
        user_otp.save()

        # Return user profile data after OTP verification

        profile_url = request.build_absolute_uri(
    reverse('profile', kwargs={'id': user.id})
)
        return Response({
    "message": "OTP verified successfully",
    "profile_url": profile_url
})

# ---------------------------
# Profile API (view & update)
# ---------------------------
class ProfileView(generics.GenericAPIView):
    serializer_class = ProfileSerializer
    permission_classes = [] 
    queryset = Profile.objects.all()
    lookup_field = 'id'  # we'll use email in URL, e.g., /profile/<email>/

    def get(self, request, id):
        """Fetch profile data by email."""
        user = get_object_or_404(User, id=id)
        profile, created = Profile.objects.get_or_create(user=user)
        # serializer = self.get_serializer(profile)
        serializer = ProfileSerializer(profile, context={'request': request}, hide_photo=True)
        # upload_photo_url = request.build_absolute_uri("/upload-photo/")

        data = serializer.data  # Get serialized profile data
        # data["Upload Photo"] = upload_photo_url  # Add the extra field

        return Response(data, status=status.HTTP_200_OK)

    def put(self, request, id):

        user = get_object_or_404(User, id=id)
        profile, created = Profile.objects.get_or_create(user=user)
        serializer = ProfileSerializer(profile, data=request.data, context={'request': request}, hide_photo=True)
        if serializer.is_valid():
            serializer.save()
            profile_view_url = request.build_absolute_uri(
    reverse('profile-detail', kwargs={'id': user.id})
)
            change_password_url = request.build_absolute_uri(
    reverse('change-password-request', kwargs={'id': user.id})
)
    

            return Response(
        {
            "message": "Your profile has been updated successfully.",
            "Profile Details": profile_view_url,
            "Change Password": change_password_url,
        },
        status=status.HTTP_200_OK
    )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, id):
        """Partially update profile data."""
        user = get_object_or_404(User, id=id)
        profile, created = Profile.objects.get_or_create(user=user)
        serializer = ProfileSerializer(profile, data=request.data, partial=True, context={'request': request}, hide_photo=True)
        if serializer.is_valid():
            serializer.save()
            profile_view_url = request.build_absolute_uri(
    reverse('profile-detail', kwargs={'id': user.id})
)
            change_password_url = request.build_absolute_uri(
    reverse('change-password-request', kwargs={'id': user.id})
)
 

            return Response(
        {
            "message": "Your profile has been updated successfully.",
        
            "Profile Details": profile_view_url,
            "Change Password": change_password_url,
        },
        status=status.HTTP_200_OK
    )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class ProfilePhotoUploadView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = ProfilePhotoSerializer

    def post(self, request):
        # 🧩 Check if image is provided
        if 'photo' not in request.FILES:
            return Response(
                {"message": "Please upload a photo."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            profile = serializer.save()
            photo_url = request.build_absolute_uri(profile.photo.url) if profile.photo else None

            return Response(
                {
                    "message": "Photo uploaded successfully.",
                    "photo_url": photo_url
                },
                status=status.HTTP_200_OK
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)    
class ProfileDetailView(generics.GenericAPIView):
    """
    View-only profile details by email.
    """
    serializer_class = ProfileSerializer
    permission_classes = [permissions.AllowAny]
    queryset = Profile.objects.all()
    lookup_field = 'id'

    def get(self, request, id):
        user = get_object_or_404(User, id=id)
        profile = get_object_or_404(Profile, user=user)
        serializer = ProfileSerializer(profile, context={'request': request}, hide_photo=True)
        profile_url = request.build_absolute_uri(
    reverse('profile', kwargs={'id': user.id})
)
        return Response(
            {
                "message": "Here are your profile details.",
                "data": serializer.data,
                "Go Back":profile_url
            },
            status=status.HTTP_200_OK
        )
    

# Forgot Password
class ForgotPasswordView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = ForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({"error": "Email not found"}, status=status.HTTP_404_NOT_FOUND)

        # ✅ Generate 6-digit OTP as string
        code = str(random.randint(100000, 999999))
        verification_otp[email] = code

        # ✅ Send OTP via email
        send_mail(
            "Password Reset Code",
            f"Your 6-digit password reset code is {code}",
            settings.DEFAULT_FROM_EMAIL,
            [email],
        )

        reset_pw_url = request.build_absolute_uri(reverse('reset-password'))
        return Response({
            "message": "Reset code sent to your email",
            "Reset Password URL": reset_pw_url
        }, status=status.HTTP_200_OK)


# Reset Password - Verify OTP and set new password
class ResetPasswordView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = ResetPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data["code"]
        new_password = serializer.validated_data["new_password"]

        # ✅ Find user by OTP
        user_identifier = None
        for key, value in verification_otp.items():
            if str(value) == str(code):  # ensure string comparison
                user_identifier = key
                break

        if not user_identifier:
            return Response({"error": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=user_identifier)
        except CustomUser.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        # ✅ Set new password
        user.set_password(new_password)
        user.save()

        # ✅ Remove OTP after successful reset
        login_url = request.build_absolute_uri(reverse('login'))
        return Response({"message": "Password reset successful.",
                         "Login Again":login_url}, status=status.HTTP_200_OK)

        
class ChangePasswordRequestView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = ChangePasswordRequestSerializer

    def post(self, request, id):
        # Get user by ID from URL
        user = get_object_or_404(User, id=id)
        email = user.email  # get email from user object

        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # Generate OTP
            otp_entry = PasswordResetOTP.generate_otp()
            PasswordResetOTP.objects.create(user=user, otp=otp_entry)

            # Send OTP via email
            send_mail(
                subject="Your Password Reset OTP",
                message=f"Your OTP code is {otp_entry}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
            )

            # URL for verifying OTP
            verify_otp_url = request.build_absolute_uri(
                reverse("verify-change-password-otp")
            )

            return Response(
                {
                    "message": "OTP has been sent to your registered email.",
                    "user_id": user.id,
                    "next": verify_otp_url,
                },
                status=status.HTTP_200_OK,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class VerifyChangePasswordOTPView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = VerifyChangePasswordOTPSerializer

    def post(self, request, *args, **kwargs):
        otp = request.data.get("otp")

        if not otp:
            return Response({"error": "OTP is required."}, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Get the latest unverified OTP entry
        otp_entry = PasswordResetOTP.objects.filter(is_verified=False).order_by("-created_at").first()
        if not otp_entry:
            return Response({"error": "No pending OTP verification found."}, status=status.HTTP_400_BAD_REQUEST)

        user = otp_entry.user  # ✅ auto-fetch user

        # ✅ Pass user to serializer context
        serializer = self.get_serializer(
            data={"otp": otp},
            context={"user": user}
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        # ✅ After OTP verified
        chng_prfl_pw = request.build_absolute_uri(reverse('prfl-reset-password'))
        return Response(
            {
                "message": "OTP verified successfully.",
                 "Change-Password":chng_prfl_pw
            },
            status=status.HTTP_200_OK
        )

class ProfResetPasswordView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = ProfResetPasswordSerializer

    def post(self, request, *args, **kwargs):
        # ✅ Get the verified user from the last OTP entry
        otp_entry = PasswordResetOTP.objects.filter(is_verified=True).order_by("-created_at").first()
        if not otp_entry:
            return Response(
                {"error": "Please verify OTP first."},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = otp_entry.user

        # ✅ Pass user in serializer context
        serializer = self.get_serializer(data=request.data, context={"user": user})
        if serializer.is_valid():
            serializer.save()
            otp_entry.delete()  # optional: remove OTP after password change

            return Response(
                {"message": "Your password has been successfully changed."},
                status=status.HTTP_200_OK
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
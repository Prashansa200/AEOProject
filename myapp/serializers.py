from rest_framework import serializers
from .models import CustomUser,Profile,PasswordResetOTP
from django.contrib.auth.hashers import make_password
import re
from django.contrib.auth import get_user_model
User = get_user_model()
# Signup
class SignupSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'email', 'password', 'confirm_password']
        extra_kwargs = {'password': {'write_only': True}}

    def validate_email(self, value):
        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        phone_pattern = r'^\d{10,15}$'
        if not (re.match(email_pattern, value) or re.match(phone_pattern, value)):
            raise serializers.ValidationError("Enter a valid email or contact number.")
        return value

    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        validated_data.pop('confirm_password')
        validated_data['password'] = make_password(validated_data['password'])
        return CustomUser.objects.create(**validated_data)

# Login
class LoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()

# OTP Verification
class OTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.IntegerField()

# Forgot Password
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

# Reset Password
class ResetPasswordSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True)
    re_enter_new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        if data.get("new_password") != data.get("re_enter_new_password"):
            raise serializers.ValidationError("Passwords do not match.")
        return data

# Profile


class ProfileSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(source='user.first_name', required=False)
    last_name = serializers.CharField(source='user.last_name', required=False)
    email = serializers.EmailField(source='user.email', read_only=True)
    photo = serializers.SerializerMethodField()  # This will show full photo URL
    photo_url = serializers.URLField(required=False, allow_blank=True, allow_null=True)

    class Meta:
        model = Profile
        fields = ['first_name', 'last_name', 'email', 'mobile_number', 'photo', 'photo_url']

    def get_photo(self, obj):
        """Return full URL of the uploaded photo."""
        request = self.context.get('request')
        if obj.photo:
            return request.build_absolute_uri(obj.photo.url)
        return None
    def __init__(self, *args, **kwargs):
        """Dynamically remove fields when context specifies."""
        hide_photo = kwargs.pop('hide_photo', False)
        super().__init__(*args, **kwargs)
        if hide_photo:
            self.fields.pop('photo', None)  
    def update(self, instance, validated_data):
        """Update profile details and optionally update photo using URL."""
        user_data = validated_data.pop('user', {})
        user = instance.user  # linked CustomUser object

        # Update user fields safely
        if 'first_name' in user_data:
            user.first_name = user_data['first_name']
        if 'last_name' in user_data:
            user.last_name = user_data['last_name']
        user.save()

        # Update other profile fields
        instance.mobile_number = validated_data.get('mobile_number', instance.mobile_number)
        instance.photo_url = validated_data.get('photo_url', instance.photo_url)
        instance.save()

        return instance

class ProfilePhotoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['photo']

    def validate_photo(self, value):
        max_size = 50 * 1024  # 50 KB
        if value and value.size > max_size:
            raise serializers.ValidationError("Profile photo size must be less than 50KB.")
        return value
    

class ChangePasswordRequestSerializer(serializers.Serializer):
    email = serializers.CharField()

    def validate(self, data):
        email = data.get("email")

        # Try to find user by email or mobile
        user = User.objects.filter(email=email).first() or \
               User.objects.filter(contact_number=email).first()

        if not user:
            raise serializers.ValidationError("No user found with this email or mobile number.")

        data["user"] = user
        return data


class VerifyChangePasswordOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        otp = data.get("otp")
        user = self.context.get("user")  # user passed via context

        if not user:
            raise serializers.ValidationError("User context is missing.")

        otp_entry = PasswordResetOTP.objects.filter(user=user, otp=otp).first()
        if not otp_entry:
            raise serializers.ValidationError("Invalid OTP.")

        if otp_entry.is_expired():
            raise serializers.ValidationError("OTP has expired. Please request a new one.")

        # Mark verified
        otp_entry.is_verified = True
        otp_entry.save()

        data["user"] = user
        return data

class ProfResetPasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    re_enter_new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = self.context.get("user")  # ✅ user passed via context

        if not user:
            raise serializers.ValidationError("User context is missing.")

        if not user.check_password(data.get("current_password")):
            raise serializers.ValidationError("Current password is incorrect.")

        if data.get("new_password") != data.get("re_enter_new_password"):
            raise serializers.ValidationError("Passwords do not match.")

        data["user"] = user
        return data

    def save(self):
        user = self.validated_data["user"]
        user.set_password(self.validated_data["new_password"])
        user.save()
        return user
from django.urls import path
from .views import (
    SignupView, LoginView, OTPVerifyView,
    ForgotPasswordView, ResetPasswordView, ProfileView,ProfileDetailView,ChangePasswordRequestView,VerifyChangePasswordOTPView,ProfResetPasswordView,ProfilePhotoUploadView
)

urlpatterns = [
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-otp/', OTPVerifyView.as_view(), name='verify-otp'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('profile/<int:id>/', ProfileView.as_view(), name='profile'),
    path('profile-detail/<int:id>/', ProfileDetailView.as_view(), name='profile-detail'),  # read-only
    path('upload-photo/', ProfilePhotoUploadView.as_view(), name='upload-photo'),
    path('change-password-request/<int:id>/', ChangePasswordRequestView.as_view(), name='change-password-request'),
    path('verify-change-password-otp/', VerifyChangePasswordOTPView.as_view(), name='verify-change-password-otp'),
    path('prfl-reset-password/', ProfResetPasswordView.as_view(), name='prfl-reset-password'),
]

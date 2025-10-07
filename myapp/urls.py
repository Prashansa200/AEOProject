from django.urls import path
from .views import (
    SignupView, LoginView, OTPVerifyView,
    ForgotPasswordView, ResetPasswordView, ProfileView,ProfileDetailView,ChangePasswordRequestView,VerifyChangePasswordOTPView,ProfResetPasswordView
)

urlpatterns = [
    path('', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('verify-otp/', OTPVerifyView.as_view(), name='verify-otp'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('profile/<str:email>/', ProfileView.as_view(), name='profile'),
    path('profile-detail/<str:email>/', ProfileDetailView.as_view(), name='profile-detail'),  # read-only
    path('change-password-request/<str:email>/', ChangePasswordRequestView.as_view(), name='change-password-request'),
    path('verify-change-password-otp/', VerifyChangePasswordOTPView.as_view(), name='verify-change-password-otp'),
    path('prfl-reset-password/', ProfResetPasswordView.as_view(), name='prfl-reset-password'),
]

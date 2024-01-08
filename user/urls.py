
from django.urls import path
from . import views

urlpatterns = [
    path('userlogin/', views.UserLogin.as_view(), name='user_login'),
    path('user/', views.UserListView.as_view(), name='user_list'),
    path('createuser/', views.UserCreateView.as_view(), name='create_user'),
    path('getotp/', views.OTPVerification.as_view(),name="get_otp"),
    path('sendmail/', views.SendResetEmail.as_view(),name="send_mail"),
    path('forgotpassword/', views.ForgotPassword.as_view(),name="forgot_password"),
]

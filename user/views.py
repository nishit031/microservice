from django.shortcuts import render
from django.contrib.auth import get_user_model
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
import json
import re
from cryptography.fernet import Fernet
from django.core.mail import send_mail
from drf_yasg.utils import swagger_auto_schema
from rest_framework.response import Response
from django.conf import settings
from rest_framework import status
from renderers import CustomJSONRenderer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import authenticate
from .serializer import UserCreateSerializer, UserForgotPassSerializer, UserLoginSerializer, UserSerializer, UserUpdateSerializer
from .models import AppUser, UserEmailOtpModel, UserMobileOtp
from rest_framework_simplejwt.tokens import RefreshToken
from authentication.models import User
import pyotp
from rest_framework.exceptions import AuthenticationFailed, ValidationError, NotFound
from rest_framework.decorators import action
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from .api_schemas import *
from .common_services.common_service import *
from rest_framework.renderers import JSONRenderer

class UserLogin(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny,]
    renderer_classes = [CustomJSONRenderer]

    @swagger_auto_schema(request_body=UserLoginSchema)
    def post(self,request, *args, **kwargs):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.get_user(serializer.validated_data)
        if not user:
            raise AuthenticationFailed('User not found.')
        
        if not self.is_password_valid(user, serializer.validated_data['password']):
            raise AuthenticationFailed('Incorrect username or password.')

        if not verify_otp(request.data):
            raise ValidationError({"detail": "OTP Verification failed."})
        
        return self.create_auth_response(user)
        
    
    def get_user(self, validated_data):
        email = validated_data.get('email')
        phone_number = validated_data.get('phone_number')

        if email:
            return AppUser.objects.filter(user__email=email, is_deleted=False).first()
        elif phone_number:
            return AppUser.objects.filter(phone_number=phone_number, is_deleted=False).first()
    
    def is_password_valid(self, user, password):
        return authenticate(email=user.user.email, password=password)
    
    def create_auth_response(self, user):
        refresh = RefreshToken.for_user(user.user)
        serializer = UserSerializer(user)
        return Response({
            'message': 'Login successfully.',
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'data': serializer.data
        }, status=status.HTTP_200_OK)
    
class UserCreateView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny,]
    renderer_classes = [CustomJSONRenderer]

    @swagger_auto_schema(request_body=UserCreateSchema)
    def post(self,request, *args, **kwargs):
        
        serializer = UserCreateSerializer(data=request.data)
        if not serializer.is_valid():
            raise ValidationError(serializer.errors)
        if not verify_otp(request.data):
            raise ValidationError({"detail": "OTP Verification failed."})
        user, created = self.get_or_create_user(request.data)
        if not created:
            raise ValidationError({"detail": "User already exists."})

        user_data = self.create_app_user(user, request.data)
        return Response({
            'message': "Data has been added!",
            'data': user_data
        }, status=status.HTTP_201_CREATED)

    def get_or_create_user(self, data):
        user = User.objects.filter(email=data['email']).first()
        if not user:
            user = get_user_model().objects.create_user(
                email=data['email'], password=data['password'])
            return user, True
        return user, False

    def create_app_user(self, user, data):
        app_user_serializer = UserCreateSerializer(data=data)
        if app_user_serializer.is_valid(raise_exception=True):
            app_user = app_user_serializer.save(user=user)
            return UserSerializer(app_user).data
        
class OTPVerification(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny,]
    renderer_classes = [CustomJSONRenderer]

    @swagger_auto_schema(request_body=OTPVerificationSchema)
    def post(self,request,*args,**kwargs):
        print(request.data)
        if request.data.get("request_for",None) == None:
            raise ValidationError({"detail": "Please provide request_for! Login or Create!"})
        if request.data.get("request_for","create") == "create":
            if check_user(request.data):
                raise ValidationError({"detail": "User Already Exist!"})
            
        if request.data.get("verify_by",None) == "phone_number":
            if not request.data.get("phone_number",None):
                raise ValidationError({"detail": "Please enter phone number!"})
            # validate phone number
            if re.match(r'^\d{10}$', request.data['phone_number']) is None:
                raise ValidationError({"detail":"Please enter valid phone number!"})
            
            OTP = self.get_phone_otp(request)
        elif request.data.get("verify_by",None) == "email":
            if not request.data.get("email",None):
                raise ValidationError({"detail": "Please enter email!"})
            if re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', request.data['email']) is None:
                raise ValidationError({"detail":"Please enter valid email!"})
            OTP = self.get_email_otp(request)
        else:
            raise ValidationError({"detail": "Please select where you'd like to receive the OTP: via email or phone"})

        return Response({
            'message': "OTP sent successfully!",
            'data': {"otp":OTP}
        }, status=status.HTTP_200_OK)

    def get_email_otp(self,request):
        request_data = request.data

        # Generate OTP
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret, interval=120)
        OTP = totp.now()
       
        OtpSaved = UserEmailOtpModel.objects.filter(email=request_data['email'])

        # if Otp in model get latest created or latest id record
        if OtpSaved:
            OtpSaved = OtpSaved.latest('id')
        # set last otp to expired if not validated
        if OtpSaved:
            OtpSaved.is_validate = False 
            OtpSaved.is_expired = True
            OtpSaved.save()

        #create new otp if number not exist in model
        UserEmailOtpModel.objects.create(email=request_data['email'],emailotp=OTP,activation_key=secret)

        # EMAIL SETUP
        # send_mail(
        #     'Subject here',
        #     'Here is the message with otp.',
        #     settings.EMAIL_HOST_USER,
        #     ['to@example.com'],
        #     fail_silently=False,
        # )

        return OTP

    
    def get_phone_otp(self,request):
        request_data = request.data

        # Generate OTP
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret, interval=120)
        OTP = totp.now()
       
        OtpSaved = UserMobileOtp.objects.filter(phone_number=request_data['phone_number'])

        # if Otp in model get latest created or latest id record
        if OtpSaved:
            OtpSaved = OtpSaved.latest('id')

        # set last otp to expired if not validated
        if OtpSaved:
            OtpSaved.is_validate = False 
            OtpSaved.is_expired = True
            OtpSaved.save()

        #create new otp if number not exist in model
        UserMobileOtp.objects.create(phone_number=request_data['phone_number'],otp=OTP,activation_key=secret)
        return OTP

class UserListView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated,]
    renderer_classes = [CustomJSONRenderer]
    def get(self,request, *args, **kwargs):
        user_obj = get_object_or_404(AppUser, user_id=request.user.pk, is_deleted=False)
        serializer = UserSerializer(user_obj)
        return Response({
            'message': "User detail!",
            'data': serializer.data
        }, status=status.HTTP_200_OK)

    @swagger_auto_schema(request_body=UpdateUserDetialPut)
    def put(self,request, *args, **kwargs):
        user_obj = get_object_or_404(AppUser, user_id=request.user.pk, is_deleted=False)
        serializer = UserUpdateSerializer(user_obj, data=request.data, partial=kwargs.get("partial", False))
        serializer.is_valid(raise_exception=True)

        if "phone_number" in request.data:
            request.data["method"] = request.method
            if not verify_otp(request.data):
                raise ValidationError("OTP verification failed.")

        self.update_password(user_obj.user, request.data)
        serializer.save()

        return Response({
            'status': 'success',
            'message': "User detail updated successfully!",
            'data': serializer.data
        }, status=status.HTTP_200_OK)

    def update_password(self, user, data):
        if 'old_password' in data and not authenticate(email=user.email, password=data['old_password']):
            raise ValidationError({"detail":"Incorrect old password."})
        if 'password' in data:
            user.set_password(data['password'])
            user.save()
    @swagger_auto_schema(request_body=UpdateUserDetialPatch)     
    def patch(self,request, *args, **kwargs):
        kwargs['partial'] = True
        return self.put(request,*args,**kwargs)

    def delete(self,request, *args, **kwargs):
        user_obj = get_object_or_404(AppUser, user_id=request.user.pk, is_deleted=False)
        user_obj.is_deleted = True
        user_obj.save()
        return Response({
            'status': 'success',
            'message': "User deleted successfully!!",
        }, status=status.HTTP_200_OK)


class ForgotPassword(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny,]
    renderer_classes = [CustomJSONRenderer]
    
    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'token', 
                in_=openapi.IN_QUERY, 
                description="Token which you got in your email", 
                type=openapi.TYPE_STRING,
                required=True
            )
        ]
    )
    def get(self, request, *args, **kwargs):
        enc_token = request.GET.get("token")
        if not enc_token:
            raise ValidationError({"detail":"token is required"})

        user_obj = get_object_or_404(AppUser, encrypted_key=enc_token)
        return Response({'status': 'success', 'message': "Verification successful!"}, status=status.HTTP_202_ACCEPTED)

    @swagger_auto_schema(request_body=ResetPassword)
    def post(self,request, *args, **kwargs):
        serializer = UserForgotPassSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_obj = self.validate_token(serializer.validated_data)
        self.reset_password(user_obj, serializer.validated_data)

        return Response({'status': 'success', 'message': "Password reset successfully!"})

    def validate_token(self, validated_data):
        user_obj = get_object_or_404(AppUser, encrypted_key=validated_data['token'])

        try:
            cipher_suite = Fernet(user_obj.cipher_key.encode())
            decrypted_data = cipher_suite.decrypt(validated_data['token'].encode()).decode()
        except:
            raise ValidationError({"detail":"Invalid token"})

        if user_obj.user.uuid_txt != decrypted_data:
            raise ValidationError({"detail":"Not authorized to perform this action"})

        return user_obj

    def reset_password(self, user_obj, validated_data):
        if validated_data["password"] != validated_data["confirm_password"]:
            raise ValidationError({"detail":"Password doesn't match"})

        user = get_user_model().objects.get(id=user_obj.user_id)
        user.set_password(validated_data['password'])
        user.save()

        user_obj.cipher_key = None
        user_obj.encrypted_key = None
        user_obj.save()
        
class SendResetEmail(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowAny,]
    renderer_classes = [CustomJSONRenderer]
    
    @swagger_auto_schema(request_body=SendResetLink)
    def post(self, request):
        if "email" not in request.data:
            raise ValidationError({"detail":"Please enter email first!"})

        if re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', request.data['email']) is None:
            raise ValidationError({"detail":"Please enter valid email!"})
        
        email = request.data['email']
        user_obj = get_object_or_404(AppUser, user__email=email, is_deleted=False)
        encrypted_data, link = self.encrypt_and_generate_link(user_obj, request)
        # EMAIL SETUP
        self.send_reset_email(email, link)

        return Response({'status': 'success', 'message': f"Reset password link {link} sent successfully!"}, status=status.HTTP_200_OK)

    def encrypt_and_generate_link(self, user_obj, request):
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)

        encrypted_data = cipher_suite.encrypt(user_obj.user.uuid_txt.encode())
        user_obj.cipher_key = key.decode()
        user_obj.encrypted_key = encrypted_data.decode()
        user_obj.save()

        host = request.get_host()
        link = f"http://{host}/api/forgotpassword/?token={encrypted_data.decode()}"

        return encrypted_data, link

    def send_reset_email(self, email, link):
        # EMAIL SETUP
        # send_mail(
        #     'Password Reset',
        #     f'Please use the following link to reset your password: {link}',
        #     settings.EMAIL_HOST_USER,
        #     [email],
        #     fail_silently=False,
        # )
        return "mail send"
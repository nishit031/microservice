from .models import *
from rest_framework import serializers
import re
from django.contrib.auth.models import User

class DjangoUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

class UserSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)
    class Meta:
        model = AppUser
        fields = '__all__'

class UserUpdateSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(required=False)
    password = serializers.CharField(required=False)
    otp = serializers.CharField(required=False)
    class Meta:
        model = AppUser
        # fields = '__all__'
        exclude = ('cipher_key','encrypted_key','create_ts','update_ts','is_deleted')

    def validate(self,data): #object leve validation
        if 'password' in data and 'old_password' not in data:
            raise serializers.ValidationError({"old_password" : "Please provide Old password!"})

        # if 'phone_number' in data and 'otp' not in data:
        #     raise serializers.ValidationError({"otp" : "For updating phone number, you have to pass otp!"})
        
        keys_to_remove = ['email', 'password', 'otp',"old_password"]
        for key in keys_to_remove:
            data.pop(key, None)
        return data

class UserForgotPassSerializer(serializers.ModelSerializer):
    password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)
    token = serializers.CharField(required=True)
    class Meta:
        model = AppUser
        fields = '__all__'

class UserLoginSerializer(serializers.ModelSerializer):
    phone_number = serializers.CharField(required=False)
    email = serializers.CharField(required=False)
    password = serializers.CharField(required=True)
    otp = serializers.CharField(required=True)

    class Meta:
        model = AppUser
        fields = '__all__'

    def validate(self,data): #object leve validation
        if 'email' not in data and 'phone_number' not in data:
            raise serializers.ValidationError({"required" : ["Phone Number or Email"]})
        
        if 'phone_number' in data:
            # Validate phone number
            if re.match(r'^\d{10}$', data['phone_number']) is None:
                raise serializers.ValidationError("Please enter valid phone number!")

        if 'email' in data:
            # validate email
            if re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', data['email']) is None:
                raise serializers.ValidationError("Please enter valid email!")
            
        return data

class UserCreateSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)
    first_name = serializers.CharField(required=True)
    phone_number = serializers.CharField(required=False)
    email = serializers.CharField(required=False)
    password = serializers.CharField(required=True)
    otp = serializers.CharField(required=True)
    class Meta:
        model = AppUser
        fields = '__all__'
    
    def create(self,data):
        keys_to_remove = ['email', 'password', 'otp']
        for key in keys_to_remove:
            data.pop(key, None)
        return AppUser.objects.create(**data)

    def validate(self,data): #object leve validation
        
        if 'email' not in data and 'phone_number' not in data:
            raise serializers.ValidationError({"required" : ["Phone Number or Email"]})
        
        if 'email' in data:
            # validate email
            if re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', data['email']) is None:
                raise serializers.ValidationError("Please enter valid email!")
        
        if 'phone_number' in data:
            # Validate phone number
            if re.match(r'^\d{10}$', data['phone_number']) is None:
                raise serializers.ValidationError("Please enter valid phone number!")
            
        return data


class MobileOtpSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserMobileOtp
        fields = '__all__'
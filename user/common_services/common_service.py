from ..models import UserEmailOtpModel, UserMobileOtp, AppUser
from django.http import JsonResponse
from rest_framework import status
import pyotp
from rest_framework.exceptions import ValidationError


def check_user(data):
    if "phone_number" in data:
        UserObj = AppUser.objects.filter(phone_number=data['phone_number']).first()
        if UserObj:
            if UserObj.phone_number != data['phone_number']:
                raise ValidationError({'detail': 'User Already Completed His Registration'})
    if "email" in data:
        UserObj = AppUser.objects.filter(user__email=data['email']).first()
        if UserObj:
            raise ValidationError({'detail': 'User Already Completed His Registration'})
    return False

def verify_otp(data):
    response = {}
    if "phone_number" in data:
        verify_by = "phone_number"
        OTPobj = UserMobileOtp.objects.filter(phone_number=data["phone_number"])
        if not OTPobj:
            raise ValidationError({'detail': f'Veirfy Your {verify_by} using OTP First!'})
    
        if OTPobj:
            if data.get("method",None) == "PUT":
                if OTPobj.latest('id').phone_number == data["phone_number"]:
                    return True
                if "otp" not in data:
                    raise ValidationError({"otp" : "For updating phone number, you have to pass otp!"})
    elif "email" in data:
        verify_by = "email"
        # if data.get("method",None) == "PUT":
        #     return True
        OTPobj = UserEmailOtpModel.objects.filter(email=data["email"])
        if not OTPobj:
            raise ValidationError({'detail': f'Veirfy Your {verify_by} using OTP First!'})
    else:
        raise ValidationError({'detail': 'Please enter valid details for verification'})
    
    OTPobj = OTPobj.latest('id')
    if OTPobj:
        # check Expired Otp or not
        if OTPobj.is_validate == True:
            raise ValidationError({'detail': 'Your Enterd OTP is Wrong!!'})
        if OTPobj.is_expired == True:
            raise ValidationError({'detail': 'Your Enterd OTP is Expired! Please try again!'})
        
        activationkey = OTPobj.activation_key
        totp = pyotp.TOTP(activationkey, interval=120)
        verify = totp.verify(data["otp"])
        if verify:
            OTPobj.is_validate = True
            OTPobj.save()
            return True
        else:
            raise ValidationError({'detail': 'Your Enterd OTP is Wrong or Expired! Please Re-enter again!'})
    raise ValidationError({'detail': f'Veirfy Your {verify_by} using OTP First!'})
from drf_yasg import openapi

UserCreateSchema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    required=['first_name', 'last_name', 'password', 'otp'],
    properties={
        'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='First name'),
        'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='Last name'),
        'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description='Phone number'),
        'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email address'),
        'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password'),
        'otp': openapi.Schema(type=openapi.TYPE_STRING, description='OTP generated via mobile or email'),
    },
)

# OTPVerification request schema
OTPVerificationSchema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    required=['request_for', 'verify_by'],
    properties={
        'request_for': openapi.Schema(type=openapi.TYPE_STRING, description='Request purpose: Login or Create', enum=['login', 'create']),
        'verify_by': openapi.Schema(type=openapi.TYPE_STRING, description='Verification method', enum=['phone_number', 'email']),
        'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description='Phone number for OTP', minLength=1),
        'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email for OTP', minLength=1),
    },
    )

UserLoginSchema = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    required=['password','otp'],
    properties={
        'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email for login'),
        'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description='Phone number for login'),
        'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password for login'),
        'otp': openapi.Schema(type=openapi.TYPE_STRING, description='OTP for login')
    }
)


ResetPassword = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    required=['token','password','confirm_password'],
    properties={
        'token': openapi.Schema(type=openapi.TYPE_STRING, description='Token for Verification'),
        'password': openapi.Schema(type=openapi.TYPE_STRING, description='New Password'),
        'confirm_password': openapi.Schema(type=openapi.TYPE_STRING, description='Confirm Password')
    }
)


SendResetLink = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    required=['email'],
    properties={
        'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email for Reset link!'),
    }
)

UpdateUserDetialPut = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    required=['first_name','last_name','phone_number','password','old_password','otp'],
    properties={
        'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='Firstname for update!'),
        'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='Lastname for update!'),
        'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description='Phone number for update!'),
        'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password for update!'),
        'old_password': openapi.Schema(type=openapi.TYPE_STRING, description='Old password for update!'),
        'otp': openapi.Schema(type=openapi.TYPE_STRING, description='OTP for update phone number!'),
    }
)

UpdateUserDetialPatch = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    required=[],
    properties={
        'first_name': openapi.Schema(type=openapi.TYPE_STRING, description='Firstname for update!'),
        'last_name': openapi.Schema(type=openapi.TYPE_STRING, description='Lastname for update!'),
        'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description='Phone number for update!'),
        'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password for update!'),
        'old_password': openapi.Schema(type=openapi.TYPE_STRING, description='Old password for update!'),
        'otp': openapi.Schema(type=openapi.TYPE_STRING, description='OTP for update phone number!'),
    }
)
SendResetLink = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    required=['email'],
    properties={
        'email': openapi.Schema(type=openapi.TYPE_STRING, description='Email for Reset link!'),
    }
)


from django.db import models
from django.contrib.auth import get_user_model

class AppUser(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE,blank=True,null=True)
    first_name = models.CharField(max_length=200,null=True,blank=True)
    last_name = models.CharField(max_length=200,null=True,blank=True)
    phone_number =  models.CharField(max_length=13,null=True,blank=False,unique=True)
    cipher_key = models.CharField(max_length=30,null=True,blank=True)
    encrypted_key = models.CharField(max_length=30,null=True,blank=True)
    create_ts = models.DateTimeField(auto_now_add=True,blank=True, null=True)
    update_ts = models.DateTimeField(auto_now=True,blank=True,null=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"


class UserMobileOtp(models.Model):
    id = models.AutoField(primary_key=True)
    phone_number = models.CharField(max_length=13,null=True,blank=False)
    otp = models.CharField(max_length=6,default="",null=True,blank=True)
    activation_key = models.CharField(max_length=150,blank=True,null=True)
    is_validate = models.BooleanField(default=False)
    is_expired = models.BooleanField(default=False)
    create_ts = models.DateTimeField(auto_now_add=True,blank=True, null=True)
    update_ts = models.DateTimeField(auto_now=True,blank=True,null=True)
    
    class Meta:
        db_table = 'phone_number_verification'
    
    def __str__(self):
        return f"{self.phone_number} - OTP: {self.otp}"

class UserEmailOtpModel(models.Model):
    id = models.AutoField(primary_key=True)
    email = models.CharField(max_length=130,null=True,blank=False)
    emailotp = models.CharField(max_length=6,default="",null=True,blank=True)
    activation_key = models.CharField(max_length=150,blank=True,null=True)
    is_validate = models.BooleanField(default=False)
    is_expired = models.BooleanField(default=False)
    create_ts = models.DateTimeField(auto_now_add=True,blank=True, null=True)
    update_ts = models.DateTimeField(auto_now=True,blank=True,null=True)
    
    class Meta:
        db_table = 'email_verification'
    
    def __str__(self):
        return f"{self.email} - OTP: {self.emailotp}"
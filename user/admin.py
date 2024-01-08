from django.contrib import admin
from .models import *
@admin.register(AppUser)
class UserAdmin(admin.ModelAdmin):
    list_display=['id']

@admin.register(UserMobileOtp)
class UserMobileOtpAdmin(admin.ModelAdmin):
    list_display=['id']

@admin.register(UserEmailOtpModel)
class UserEmailOtpAdmin(admin.ModelAdmin):
    list_display=['id']


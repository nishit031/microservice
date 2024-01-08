# Generated by Django 3.2 on 2024-01-08 06:59

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserEmailOtpModel',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('email', models.CharField(max_length=130, null=True)),
                ('emailotp', models.CharField(blank=True, default='', max_length=6, null=True)),
                ('activation_key', models.CharField(blank=True, max_length=150, null=True)),
                ('is_validate', models.BooleanField(default=False)),
                ('is_expired', models.BooleanField(default=False)),
                ('create_ts', models.DateTimeField(auto_now_add=True, null=True)),
                ('update_ts', models.DateTimeField(auto_now=True, null=True)),
            ],
            options={
                'db_table': 'email_verification',
            },
        ),
        migrations.CreateModel(
            name='UserMobileOtp',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('phone_number', models.CharField(max_length=13, null=True)),
                ('otp', models.CharField(blank=True, default='', max_length=6, null=True)),
                ('activation_key', models.CharField(blank=True, max_length=150, null=True)),
                ('is_validate', models.BooleanField(default=False)),
                ('is_expired', models.BooleanField(default=False)),
                ('create_ts', models.DateTimeField(auto_now_add=True, null=True)),
                ('update_ts', models.DateTimeField(auto_now=True, null=True)),
            ],
            options={
                'db_table': 'phone_number_verification',
            },
        ),
        migrations.CreateModel(
            name='AppUser',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('first_name', models.CharField(blank=True, max_length=200, null=True)),
                ('last_name', models.CharField(blank=True, max_length=200, null=True)),
                ('phone_number', models.CharField(max_length=13, null=True, unique=True)),
                ('cipher_key', models.CharField(blank=True, max_length=30, null=True)),
                ('encrypted_key', models.CharField(blank=True, max_length=30, null=True)),
                ('create_ts', models.DateTimeField(auto_now_add=True, null=True)),
                ('update_ts', models.DateTimeField(auto_now=True, null=True)),
                ('is_deleted', models.BooleanField(default=False)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
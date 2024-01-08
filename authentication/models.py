import uuid
from datetime import datetime, timezone as tz

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin, User
from django.db import IntegrityError, models
from django.utils import timezone
from django.utils.translation import gettext as _


class UserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifier for 
    authentication instead of username.
    """
    def _save_user(self, user):
        try:
            user.generate_and_set_uuid_txt()
            user.save(using=self._db)
        except IntegrityError as err:
            # UniqueViolation: duplicate key value for "uuid_txt" field
            if err.__cause__.pgcode == 23505:
                self._save_user(user)

    def _create_user(self, email, password=None, **extra_fields):
        """Creates and saves a user with the given email, password and other
        information.

        Parameters
        ----------
        email : str
            Email of the user
        password : str, optional
            Password of the user, by default None
        Returns
        -------
        User
            The User object.
        """
        if not email:
            raise ValueError('Users must have an email address')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        self._save_user(user)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """Creates and saves a user with the given email, password and other
        information.

        Parameters
        ----------
        email : str
            Email of the user
        password : str, optional
            Password of the user, by default None

        Returns
        -------
        User
            The User object.
        """
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        """Creates and saves a superuser with the given email, password and
        other information.

        Parameters
        ----------
        email : str
            Email of the user
        password : str, optional
            Password of the user, by default None

        Returns
        -------
        User
            The User object.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model with email as the primary identifier field.
    """
    email = models.EmailField(_('email address'),max_length=255,unique=True,)
    is_staff = models.BooleanField(_('staff status'),default=False,help_text=_('Designates whether the user can log into this admin site.'),)
    is_active = models.BooleanField(_('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    uuid_txt = models.CharField(
        _('uuid text'),
        max_length=36,
        unique=True,
        help_text=_(
            'UUID representing this user. '
            'Helps identify this user without their user ID and can be shared publicly.'
        ),
        error_messages={
            'unique': _('A user with that uuid_txt already exists.'),
        },
    )
    deleted = models.DateTimeField(default=None,blank=True, null=True)
    is_deleted = models.BooleanField(default=False)

    class Meta:
        permissions = (
            ("can_go_in_non_ac_bus", "To provide non-AC Bus facility"),
            ("can_go_in_ac_bus", "To provide AC-Bus facility"),
            ("can_stay_ac-room", "To provide staying at AC room"),
            ("can_stay_ac-room", "To provide staying at Non-AC room"),
            ("can_go_dehradoon", "Trip to Dehradoon"),
            ("can_go_mussoorie", "Trip to Mussoorie"),
            ("can_go_haridwaar", "Trip to Haridwaar"),
            ("can_go_rishikesh", "Trip to Rishikesh")
        )
    
    def softDelete(self):
        self.is_deleted = True
        self.deleted = datetime.now(tz.utc)
        self.save()

    objects = UserManager()

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        db_table = 'user'
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)
    
    def generate_and_set_uuid_txt(self):
        """Generate a uuid"""
        self.uuid_txt = str(uuid.uuid4())
    
    def __str__(self):
        return self.email
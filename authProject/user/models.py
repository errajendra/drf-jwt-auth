from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.base_user import BaseUserManager
from django.core.validators import RegexValidator
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password



class CustomUserManager(BaseUserManager):
    
    def create_user(self, email, password, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not email:
            raise ValueError('Users must have an email address')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_staffuser(self, email, password):
        """
        Creates and saves a staff user1 with the given email and password.
        """
        user = self.create_user(
            email,
            password=password
        )
        user.is_staff = True
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        """
        Creates and saves a superuser with the given email and password.
        """
        user = self.create_user(
            email,
            password=password,
        )
        user.email_verified = True
        user.is_staff = True
        user.is_admin = True
        user.is_superuser = True
        user.is_active = True
        user.save(using=self._db)
        return user
    

class LowercaseEmailField(models.EmailField):
    """
    Override EmailField to convert emails to lowercase before saving.
    """
    def to_python(self, value):
        """
        Convert email to lowercase.
        """
        value = super(LowercaseEmailField, self).to_python(value)
        # Value can be None so check that it's a string before lowercasing.
        if isinstance(value, str):
            return value.lower()
        return value


class CustomUser(AbstractBaseUser, PermissionsMixin):
    
    first_name = models.CharField(_("First Name"), max_length=50, blank=True)
    last_name = models.CharField(_("Last Name"), max_length=50, blank=True)
    email = LowercaseEmailField(_("email address"), unique=True)
    phone = models.BigIntegerField(validators=[RegexValidator(r"^[6-9]\d{9}$", "Enter valid mobile number.")],
                                   null=True, blank=True)
    otp = models.CharField(max_length=7, null=True, blank=True)
    email_verified = models.BooleanField(default=False)
    
    is_superuser = models.BooleanField(_("superuser status"),default=False)
    is_admin = models.BooleanField(_("admin status"), default=False)
    is_staff = models.BooleanField(_("staff status"), default=False)
    is_active = models.BooleanField(_("account status"), default=False)
    
    objects = CustomUserManager()
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    EMAIL_FIELD = "email"
    USERNAME_FIELD = "email"

    class Meta:
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        if len(self.password) < 25:
            self.password = make_password(self.password)
        super().save(*args, **kwargs)
        
    def full_name(self):
        return f'{self.first_name} {self.last_name}'

    def email_user(self, subject, message, from_email=None, **kwargs):
        send_mail(subject, message, from_email, [self.email], **kwargs)



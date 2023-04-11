from django.contrib import admin
from .models import CustomUser

class UserAdmin(admin.ModelAdmin)
  list_display = ("email", "is_active")


admin.site.register(CustomUser)

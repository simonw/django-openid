from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin
from django.contrib import admin
from django.contrib.admin.sites import NotRegistered

from models import UserOpenidAssociation

class OpenIDInline(admin.StackedInline):
    model = UserOpenidAssociation

class UserAdminWithOpenIDs(UserAdmin):
    inlines = [OpenIDInline]

# Add OpenIDs to the user admin, but only if User has been registered
try:
    admin.site.unregister(User)
    admin.site.register(User, UserAdminWithOpenIDs)
except NotRegistered:
    pass

#from models import Nonce, Association
#admin.site.register(Nonce)
#admin.site.register(Association)

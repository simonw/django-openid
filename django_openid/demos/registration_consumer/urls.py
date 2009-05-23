from django.conf.urls.defaults import *
from django.http import HttpResponseRedirect
from django_openid.registration import RegistrationConsumer

urlpatterns = patterns('',
    (r'^$', lambda r: HttpResponseRedirect('/openid/')),
    (r'^openid/(.*)', RegistrationConsumer()),
)

from django.conf.urls.defaults import *
from django.http import HttpResponse
from django_openid.registration import RegistrationConsumer

urlpatterns = patterns('',
    (r'^$', lambda r: HttpResponse('Index')),
    (r'^openid/(.*)', RegistrationConsumer()),
)

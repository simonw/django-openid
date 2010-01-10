from django.conf.urls.defaults import *
from django.http import HttpResponseRedirect
from django_openid.registration import RegistrationConsumer

class NoSignNext(RegistrationConsumer):
    sign_next_param = False

urlpatterns = patterns('',
    (r'^$', lambda r: HttpResponseRedirect('/openid/')),
    (r'^openid/(.*)', NoSignNext()),
)

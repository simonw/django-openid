from django.conf.urls.defaults import *
from django.http import HttpResponseRedirect
from django_openid.consumer import Consumer

urlpatterns = patterns('',
    (r'^$', lambda r: HttpResponseRedirect('/openid/')),
    (r'^openid/(.*)', Consumer()),
)

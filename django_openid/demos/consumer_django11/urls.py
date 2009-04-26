from django.conf.urls.defaults import *
from django.http import HttpResponseRedirect
from django_openid.consumer import Consumer

consumer = Consumer()

urlpatterns = patterns('',
    (r'^$', lambda r: HttpResponseRedirect('/openid/')),
    # As of Django 1.1 (actually changeset [9739]) you can use include here:
    (r'^openid/', include(consumer.urls)),
)

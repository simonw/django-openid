from django.conf.urls.defaults import *
from django.http import HttpResponseRedirect
from anon_provider import AnonProvider, openid_page

urlpatterns = patterns('',
    (r'^$', lambda r: HttpResponseRedirect('/openid/')),
    (r'^server/$', AnonProvider()),
    (r'^(\w+)/$', openid_page),
)

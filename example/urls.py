from django.conf.urls.defaults import *
import views

urlpatterns = patterns('',
    (r'^$', views.index),
    (r'^openid/$', 'django_openidconsumer.views.begin', {
        'sreg': 'email,nickname'
    }),
    (r'^openid/complete/$', 'django_openidconsumer.views.complete'),
)

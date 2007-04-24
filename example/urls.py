from django.conf.urls.defaults import *
import views

urlpatterns = patterns('',
    (r'^$', views.index),
    (r'^openid/$', 'django_openidconsumer.views.begin'),
    (r'^openid/with-sreg/$', 'django_openidconsumer.views.begin', {
        'sreg': 'email,nickname',
        'redirect_to': '/openid/complete/',
    }),
    (r'^openid/complete/$', 'django_openidconsumer.views.complete'),
    (r'^openid/signout/$', 'django_openidconsumer.views.signout'),
)

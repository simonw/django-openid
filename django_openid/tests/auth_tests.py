from django.test import TestCase
from django.test.client import Client
from django.http import Http404
from django.conf import settings

from django_openid.registration import RegistrationConsumer
from django_openid import signed

from django.contrib.auth.models import User
from django.utils.decorators import decorator_from_middleware
from request_factory import RequestFactory
from openid_mocks import *

from openid.consumer import consumer as janrain_consumer

rf = RequestFactory()

class AuthTest(TestCase):
    urls = 'django_openid.tests.auth_test_urls'
    
    def setUp(self):
        # Monkey-patch in the correct middleware
        self.old_middleware = settings.MIDDLEWARE_CLASSES
        settings.MIDDLEWARE_CLASSES = (
            'django.middleware.common.CommonMiddleware',
            'django.contrib.sessions.middleware.SessionMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django_openid.registration.RegistrationConsumer',
        )
        
        # Create user accounts associated with OpenIDs
        self.no_openids = User.objects.create(username = 'no-openids')
        self.no_openids.set_password('password')
        self.no_openids.save()
        self.one_openid = User.objects.create(username = 'one-openid')
        self.one_openid.openids.create(openid = 'http://a.example.com/')
        self.two_openid = User.objects.create(username = 'two-openids')
        self.two_openid.openids.create(openid = 'http://b.example.com/')
        self.two_openid.openids.create(openid = 'http://c.example.com/')
    
    def tearDown(self):
        settings.MIDDLEWARE_CLASSES = self.old_middleware
    
    def testLoginWithPassword(self):
        response = self.client.post('/openid/login/', {
            'username': 'no-openids',
            'password': 'incorrect-password',
        })
        self.assertEqual(
            response.template_name, 'django_openid/login_plus_password.html'
        )
        response = self.client.post('/openid/login/', {
            'username': 'no-openids',
            'password': 'password',
        })
        self.assertRedirects(response, '/')

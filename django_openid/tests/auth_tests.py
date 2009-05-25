from django.test import TestCase
from django.test.client import Client
from django.http import Http404
from django.conf import settings
from django.core import mail

from django_openid.registration import RegistrationConsumer
from django_openid import signed

from django.contrib.auth.models import User
from django.utils.decorators import decorator_from_middleware
from request_factory import RequestFactory
from openid_mocks import *

from openid.consumer import consumer as janrain_consumer

rf = RequestFactory()

class AuthTestBase(TestCase):
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
        self.no_openids = User.objects.create(username = 'noopenids')
        self.no_openids.set_password('password')
        self.no_openids.save()
        self.one_openid = User.objects.create(username = 'oneopenid')
        self.one_openid.openids.create(openid = 'http://a.example.com/')
        self.two_openid = User.objects.create(username = 'twoopenids')
        self.two_openid.openids.create(openid = 'http://b.example.com/')
        self.two_openid.openids.create(openid = 'http://c.example.com/')
    
    def tearDown(self):
        settings.MIDDLEWARE_CLASSES = self.old_middleware

class AuthTest(AuthTestBase):
    
    def testLoginWithPassword(self):
        response = self.client.post('/openid/login/', {
            'username': 'noopenids',
            'password': 'incorrect-password',
        })
        self.assertEqual(
            response.template_name, 'django_openid/login_plus_password.html'
        )
        response = self.client.post('/openid/login/', {
            'username': 'noopenids',
            'password': 'password',
        })
        self.assertRedirects(response, '/')

class RegistrationTest(AuthTestBase):
    
    def testInvalidRegistrationWithPassword(self):
        response = self.client.post('/openid/register/', data = {
            'username': 'noopenids', # already in use
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@example.com',
            'password': 'password',
            'password2': 'password',
        })
        self.assertEqual(
            response.template_name, 'django_openid/register.html'
        )
        self.assert_(
            'User with this Username already exists' in str(response)
        )
    
    def testRegisterWithPassword(self):
        self.assertEqual(len(mail.outbox), 0)
        response = self.client.post('/openid/register/', data = {
            'username': 'newuser', # already in use
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@example.com',
            'password': 'password',
            'password2': 'password',
        })
        self.assertEqual(
            response.template_name, 'django_openid/register_email_sent.html'
        )
        # newuser should belong to 'Unconfirmed users' and have is_active=0
        user = User.objects.get(username = 'newuser')
        self.assertEqual(user.is_active, False)
        self.assertEqual(
            user.groups.filter(name = 'Unconfirmed users').count(), 1
        )
        # An e-mail should have been sent
        self.assertEqual(len(mail.outbox), 1)
        
        # Now extract and click that link
        body = mail.outbox[0].body
        link = [
            l.strip() for l in body.splitlines()
            if l.startswith('http://testserver/')
        ][0]
        response = self.client.get(link)
        self.assertEqual(
            response.template_name, 'django_openid/register_complete.html'
        )
        
        user = User.objects.get(username = 'newuser')
        self.assertEqual(user.is_active, True)
        self.assertEqual(
            user.groups.filter(name = 'Unconfirmed users').count(), 0
        )

from django.test import TestCase
from django.test.client import Client
from django.http import Http404
from django_openid.registration import RegistrationConsumer
from django_openid import signed
from django.contrib.auth.models import User

from request_factory import RequestFactory
from openid_mocks import *

from openid.consumer import consumer as janrain_consumer

rf = RequestFactory()

class AuthTest(TestCase):
    
    def setUp(self):
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
        [user.delete() for user in User.objects.filter(username__in = (
            'no-openids', 'one-openid', 'two-openids'
        ))]
    
    def testLoginWithPassword(self):
        client = Client()
        response = client.post('/openid/login/', {
            'username': 'no-openids',
            'password': 'incorrect-password',
        })
        # Should get the login page again
        self.assert_('login' in response.template_name)
        
        response = client.post('/openid/login/', {
            'username': 'no-openids',
            'password': 'password',
        })
        # Should be a redirect
        self.assert_(response.has_header('Location'))

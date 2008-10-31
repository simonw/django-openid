from django.test import TestCase
from django.http import Http404
from django_openid.consumer import Consumer
from django_openid import signed

from request_factory import RequestFactory
from openid_mocks import *

from openid.consumer import consumer as janrain_consumer

rf = RequestFactory()

class AuthTest(TestCase):
    
    def setUp(self):
        # Create user accounts associated with OpenIDs
        self.no_openids = User.objects.create(username = 'no-openids')
        self.one_openid = User.objects.create(username = 'one-openid')
        self.one_openid.openids.create(openid = 'http://a.example.com/')
        self.two_openid = User.objects.create(username = 'two-openids')
        self.two_openid.openids.create(openid = 'http://b.example.com/')
        self.two_openid.openids.create(openid = 'http://c.example.com/')
    
    def testLogin(self):
        
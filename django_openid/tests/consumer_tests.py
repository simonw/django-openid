from django.test import TestCase
from django_openid.consumer import Consumer
from request_factory import RequestFactory

rf = RequestFactory()

class MockAuthRequest(object):
    def __init__(self, consumer):
        self.consumer = consumer
    
    def redirectURL(self, trust_root, on_complete_url):
        return self.consumer.redirect_url

class MockConsumer(object):
    def __init__(self, user_url, redirect_url, raise_discover_failure=None):
        self.user_url = user_url
        self.redirect_url = redirect_url
        self.raise_discover_failure = raise_discover_failure
    
    def begin(self, user_url):
        from openid.consumer.discover import DiscoveryFailure
        assert user_url == self.user_url
        if self.raise_discover_failure:
            raise DiscoveryFailure
        return MockAuthRequest(self)

class MockOpenIDConsumer(Consumer):
    def get_consumer(self, request, session_store):
        return MockConsumer(
            user_url = 'http://simonwillison.net/',
            redirect_url = 'http://url-of-openid-server/',
        )

class ConsumerTest(TestCase):
    
    def testCanLogin(self):
        "Can log in with an OpenID"
        openid_consumer = MockOpenIDConsumer()
        post = rf.post('/submit/', {
            'openid_url': 'http://simonwillison.net/'
        })
        post.session = {}
        response = openid_consumer(post)
        self.assertEqual(response['Location'], 'http://url-of-openid-server/')
        
        

"""
Mock objects for the bits of the OpenID flow that would normally involve 
communicating with an external service.
"""
from django_openid.consumer import Consumer, SessionConsumer, CookieConsumer
from django_openid.auth import AuthConsumer
from openid.message import Message

class MockSession(dict):
    def __init__(self, **kwargs):
        super(MockSession, self).__init__(**kwargs)
        self.modified = False

class MockAuthRequest(object):
    def __init__(self, consumer):
        self.consumer = consumer
    
    def redirectURL(self, trust_root, on_complete_url):
        return self.consumer.redirect_url

class MockOpenIDResponse(object):
    def __init__(self, status, identity_url):
        self.status = status
        self.identity_url = identity_url
        self.message = Message()
    
    def getSignedNS(self, *args):
        return {}

class MockConsumer(object):
    def __init__(self, consumer, user_url, redirect_url, session_store,
            raise_discover_failure=None):
        self.consumer = consumer
        self.user_url = user_url
        self.redirect_url = redirect_url
        self.session_store = session_store
        self.raise_discover_failure = raise_discover_failure
    
    def complete(self, *args, **kwargs):
        return self.consumer._mock_response
    
    def begin(self, user_url):
        from openid.consumer.discover import DiscoveryFailure
        if self.raise_discover_failure:
            raise DiscoveryFailure(500, 'Error')
        self.session_store['openid_bits'] = {'foo': 'bar'}
        return MockAuthRequest(self)

class MyDiscoverFailConsumer(Consumer):
    def get_consumer(self, request, session_store):
        return MockConsumer(
            consumer = self,
            user_url = 'http://simonwillison.net/',
            redirect_url = 'http://url-of-openid-server/',
            session_store = session_store,
            raise_discover_failure = True,
        )

class MyConsumerMixin(object):
    def get_consumer(self, request, session_store):
        return MockConsumer(
            consumer = self,
            user_url = 'http://simonwillison.net/',
            redirect_url = 'http://url-of-openid-server/',
            session_store = session_store,
        )
    
    def set_mock_response(self, status, identity_url):
        self._mock_response = MockOpenIDResponse(status, identity_url)

class MyConsumer(MyConsumerMixin, Consumer):
    pass

class MySessionConsumer(MyConsumerMixin, SessionConsumer):
    pass

class MyCookieConsumer(MyConsumerMixin, CookieConsumer):
    pass

class MyAuthConsumer(MyConsumerMixin, AuthConsumer):
    pass

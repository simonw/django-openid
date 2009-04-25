from django.test import TestCase
from django.http import Http404
from django_openid.consumer import Consumer
from django_openid import signed

from request_factory import RequestFactory
from openid_mocks import *

from openid.consumer import consumer as janrain_consumer

rf = RequestFactory()

class ConsumerTest(TestCase):
    
    def testBadMethod(self):
        "Non existent methods should result in a 404"
        openid_consumer = MyConsumer()
        get = rf.get('/openid/foo/')
        self.assertRaises(Http404, openid_consumer, get, 'foo/')
    
    def testLoginBegin(self):
        "Can log in with an OpenID"
        openid_consumer = MyConsumer()
        post = rf.post('/openid/', {
            'openid_url': 'http://simonwillison.net/'
        })
        post.session = MockSession()
        response = openid_consumer(post)
        self.assertEqual(response['Location'], 'http://url-of-openid-server/')
        oid_session = signed.loads(response.cookies['o_user_session'].value)
        self.assert_('openid_bits' in oid_session)
    
    def testLoginDiscoverFail(self):
        "E.g. the user enters an invalid URL"
        openid_consumer = MyDiscoverFailConsumer()
        post = rf.post('/openid/', {
            'openid_url': 'not-an-openid'
        })
        post.session = MockSession()
        response = openid_consumer(post)
        self.assert_(openid_consumer.openid_invalid_message in str(response))
    
    def testLoginSuccess(self):
        "Simulate a successful login"
        openid_consumer = MyConsumer()
        openid_consumer.set_mock_response(
            status = janrain_consumer.SUCCESS,
            identity_url = 'http://simonwillison.net/',
        )
        get = rf.get('/openid/complete/', {'openid-args': 'go-here'})
        get.session = MockSession()
        response = openid_consumer(get, 'complete/')
        self.assert_(
            'You logged in as http://simonwillison.net/' in response.content
        )
    
    def testLoginNext(self):
        "?next=<signed> causes final redirect to go there instead"
        openid_consumer = MyConsumer()
        openid_consumer.set_mock_response(
            status = janrain_consumer.SUCCESS,
            identity_url = 'http://simonwillison.net/',
        )
        get = rf.get('/openid/complete/', {
            'openid-args': 'go-here',
            'next': openid_consumer.sign_next('/foo/')
        })
        get.session = MockSession()
        response = openid_consumer(get, 'complete/')
        self.assertEqual(response['Location'], '/foo/')
    
    def testLoginCancel(self):
        openid_consumer = MyConsumer()
        openid_consumer.set_mock_response(
            status = janrain_consumer.CANCEL,
            identity_url = 'http://simonwillison.net/',
        )
        get = rf.get('/openid/complete/', {'openid-args': 'go-here'})
        get.session = MockSession()
        response = openid_consumer(get, 'complete/')
        self.assert_(
            openid_consumer.request_cancelled_message in response.content
        )
    
    def testLoginFailure(self):
        openid_consumer = MyConsumer()
        openid_consumer.set_mock_response(
            status = janrain_consumer.FAILURE,
            identity_url = 'http://simonwillison.net/',
        )
        get = rf.get('/openid/complete/', {'openid-args': 'go-here'})
        get.session = MockSession()
        response = openid_consumer(get, 'complete/')
        self.assert_('Failure: ' in response.content)
    
    def testLoginSetupNeeded(self):
        openid_consumer = MyConsumer()
        openid_consumer.set_mock_response(
            status = janrain_consumer.SETUP_NEEDED,
            identity_url = 'http://simonwillison.net/',
        )
        get = rf.get('/openid/complete/', {'openid-args': 'go-here'})
        get.session = MockSession()
        response = openid_consumer(get, 'complete/')
        self.assert_(openid_consumer.setup_needed_message in response.content)
    
    def testLogo(self):
        openid_consumer = MyConsumer()
        get = rf.get('/openid/logo/')
        response = openid_consumer(get, 'logo/')
        self.assert_('image/gif' in response['Content-Type'])

class SessionConsumerTest(TestCase):
    
    def login(self):
        openid_consumer = MySessionConsumer()
        openid_consumer.set_mock_response(
            status = janrain_consumer.SUCCESS,
            identity_url = 'http://simonwillison.net/',
        )
        get = rf.get('/openid/complete/', {'openid-args': 'go-here'})
        get.session = MockSession()
        response = openid_consumer(get, 'complete/')
        return get, response
    
    def testLogin(self):
        "Simulate a successful login"
        request, response = self.login()
        self.assertEqual(response['Location'], '/')
        self.assert_('openids' in request.session)
        self.assertEqual(len(request.session['openids']), 1)
        self.assertEqual(
            request.session['openids'][0].openid, 'http://simonwillison.net/'
        )
    
    def testLogout(self):
        request, response = self.login()
        get = rf.get('/openid/logout/')
        get.session = request.session
        openid_consumer = MySessionConsumer()
        response = openid_consumer(get, 'logout/')
        self.assertEqual(response['Location'], '/')
        self.assertEqual(len(request.session['openids']), 0)

class CookieConsumerTest(TestCase):
    
    def login(self):
        openid_consumer = MyCookieConsumer()
        openid_consumer.set_mock_response(
            status = janrain_consumer.SUCCESS,
            identity_url = 'http://simonwillison.net/',
        )
        get = rf.get('/openid/complete/', {'openid-args': 'go-here'})
        response = openid_consumer(get, 'complete/')
        return get, response
    
    def testLogin(self):
        "Simulate a successful login"
        request, response = self.login()
        self.assert_('openid' in response.cookies, 'openid cookie not set')
        self.assertEqual(response['Location'], '/')
        # Decrypt the cookie and check it's the right thing
        cookie = response.cookies['openid'].value
        openid = signed.loads(
            cookie, extra_salt = MyCookieConsumer().extra_salt
        )
        self.assertEqual(openid.openid, 'http://simonwillison.net/')
    
    def testLogout(self):
        request, response = self.login()
        get = rf.get('/openid/logout/')
        openid_consumer = MyCookieConsumer()
        response = openid_consumer(get, 'logout/')
        self.assert_('openid' in response.cookies, 'openid cookie not set')
        self.assertEqual(response['Location'], '/')
        self.assertEqual(response.cookies['openid'].value, '')


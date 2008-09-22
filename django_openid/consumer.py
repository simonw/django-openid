"""
Consumer is a class-based generic view which handles all aspects of consuming
and providing OpenID. User applications should define subclasses of this, 
then hook those up directly to the urlconf.

from myapp import MyConsumerSubclass

urlpatterns = patterns('',
    ('r^openid/(.*)', MyConsumerSubclass()),
    ...
)
"""
from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.shortcuts import render_to_response

from openid.consumer import consumer
from openid.consumer.discover import DiscoveryFailure
from openid.yadis import xri

from django_openid.models import DjangoOpenIDStore
from django_openid.utils import OpenID
from django_openid import signed

class SessionUserSessionMixin(object):
    def get_user_session(self, request):
        return request.session
    def set_user_session(self, request, response, user_session):
        pass

class CookieUserSessionMixin(object):
    """
    Use this mixin if you are avoiding Django's session support entirely.
    """
    cookie_user_session_key = 'o_user_session'
    cookie_user_session_path = '/'
    cookie_user_session_domain = None
    cookie_user_session_secure = None
    
    def get_user_session(self, request):
        print "CookieUserSessionMixin: get_user_session"
        # By default Consumer uses Django sessions; here we over-ride so it 
        # works using signed cookies instead.
        try:
            user_session = signed.loads(
                request.COOKIES.get(self.cookie_user_session_key, '')
            )
        except ValueError:
            user_session = {}
        return user_session
    
    def set_user_session(self, request, response, user_session):
        print "CookieUserSessionMixin: set_user_session"
        if user_session:
            response.set_cookie(
                key = self.cookie_user_session_key,
                value = signed.dumps(user_session, compress = True),
                path = self.cookie_user_session_path,
                domain = self.cookie_user_session_domain,
                secure = self.cookie_user_session_secure,
            )
        else:
            response.delete_cookie(
                key = self.cookie_user_session_key,
                path = self.cookie_user_session_path,
                domain = self.cookie_user_session_domain,
            )

class Consumer(object):
    # Default templates
    base_template = 'django_openid/base.html'
    login_template = 'django_openid/login.html'
    error_template = 'django_openid/error.html'
    message_template = 'django_openid/message.html'
    
    # Extension args; most of the time you'll just need the sreg shortcuts
    extension_args = {}
    extension_namespaces = {
        'sreg': 'http://openid.net/sreg/1.0',
    }
    
    # Simple registration. Possible fields are:
    # nickname,email,fullname,dob,gender,postcode,country,language,timezone
    sreg = sreg_optional = [] # sreg is alias for sreg_optional
    sreg_required = [] # Recommend NOT using this; use sreg instead
    sreg_policy_url = None
    
    # Default messages
    openid_required_message = 'Enter an OpenID'
    xri_disabled_message = 'i-names are not supported'
    openid_invalid_message = 'The OpenID was invalid'
    request_cancelled_message = 'The request was cancelled'
    failure_message = 'Failure: %s'
    setup_needed_message = 'Setup needed'
    
    xri_enabled = False
    on_complete_url = None
    trust_root = None # If None, full URL to endpoint is used
    logo_path = None # Path to the OpenID logo, as used by the login view
    
    OPENID_LOGO_BASE_64 = """
R0lGODlhEAAQAMQAAO3t7eHh4srKyvz8/P5pDP9rENLS0v/28P/17tXV1dHEvPDw8M3Nzfn5+d3d
3f5jA97Syvnv6MfLzcfHx/1mCPx4Kc/S1Pf189C+tP+xgv/k1N3OxfHy9NLV1/39/f///yH5BAAA
AAAALAAAAAAQABAAAAVq4CeOZGme6KhlSDoexdO6H0IUR+otwUYRkMDCUwIYJhLFTyGZJACAwQcg
EAQ4kVuEE2AIGAOPQQAQwXCfS8KQGAwMjIYIUSi03B7iJ+AcnmclHg4TAh0QDzIpCw4WGBUZeikD
Fzk0lpcjIQA7""".strip()
    
    def render(self, request, template, context=None):
        context = context or {}
        context['base_template'] = self.base_template
        return render_to_response(template, context)
    
    def __call__(self, request, rest_of_url=''):
        if not request.path.endswith('/'):
            return HttpResponseRedirect(request.path + '/')
        
        # Dispatch based on path component
        part = rest_of_url.split('/')[0]
        if not part:
            return self.do_login(request)
        if not hasattr(self, 'do_%s' % part):
            raise Http404, 'No do_%s method' % part
        return getattr(self, 'do_%s' % part)(request)
    
    def show_login(self, request, message=None):
        try:
            done = signed.loads(request.REQUEST.get('done', ''))
        except ValueError:
            done = ''
        return self.render(request, self.login_template, {
            'action': request.path,
            'logo': self.logo_path or (request.path + 'logo/'),
            'message': message,
            'done': done,
        })
    
    def show_error(self, request, message):
        return self.render(request, self.error_template, {
            'message': message,
        })
    
    def show_message(self, request, title, message):
        return self.render(request, self.message_template, {
            'title': title,
            'message': message,
        })
    
    def get_consumer(self, request, session_store):
        return consumer.Consumer(session_store, DjangoOpenIDStore())
    
    def add_extension_args(self, request, auth_request):
        # Add extension args (for things like simple registration)
        extension_args = dict(self.extension_args) # Create a copy
        if self.sreg:
            extension_args['sreg.optional'] = ','.join(self.sreg)
        if self.sreg_required:
            extension_args['sreg.required'] = ','.join(self.sreg_required)
        if self.sreg_policy_url:
            extension_args['sreg.policy_url'] = self.sreg_policy_url
        
        for name, value in extension_args.items():
            namespace, key = name.split('.', 1)
            namespace = self.extension_namespaces.get(namespace, namespace)
            auth_request.addExtensionArg(namespace, key, value)
    
    def do_login(self, request):
        if request.method == 'GET':
            return self.show_login(request)
        
        user_url = request.POST.get('openid_url', None)
        if not user_url:
            return self.show_login(request, self.openid_required_message)
        
        if xri.identifierScheme(user_url) == 'XRI' and not self.xri_enabled:
            return self.show_login(request, self.xri_disabled_message)
        
        user_session = self.get_user_session(request)
        
        try:
            auth_request = self.get_consumer(
                request, user_session
            ).begin(user_url)
        except DiscoveryFailure:
            return self.show_error(request, self.openid_invalid_message)
        
        trust_root = self.trust_root or request.build_absolute_uri()
        on_complete_url = self.on_complete_url or \
            request.build_absolute_uri() + 'complete/'
        
        self.add_extension_args(request, auth_request)
        
        redirect_url = auth_request.redirectURL(trust_root, on_complete_url)
        response = HttpResponseRedirect(redirect_url)
        self.set_user_session(request, response, user_session)
        return response
    
    def get_user_session(self, request):
        print "Consumer: get_user_session"
        return request.session
    
    def set_user_session(self, request, response, user_session):
        print "Consumer: set_user_session"
        pass
    
    def do_complete(self, request):
        user_session = self.get_user_session(request)
        
        openid_response = self.get_consumer(
            request, user_session
        ).complete(
            dict(request.GET.items()),
            request.build_absolute_uri().split('?')[0] # to verify return_to
        )
        if openid_response.status == consumer.SUCCESS:
            response = self.on_success(
                request, openid_response.identity_url, openid_response
            )
        else:
            response = {
                consumer.CANCEL: self.on_cancel,
                consumer.FAILURE: self.on_failure,
                consumer.SETUP_NEEDED: self.on_setup_needed,
            }[openid_response.status](request, openid_response)
        
        self.set_user_session(request, response, user_session)
        
        return response
    
    def do_debug(self, request):
        if not settings.DEBUG:
            raise Http404
        assert False, 'debug!'
    
    def on_success(self, request, identity_url, openid_response):
        # This is the one method you REALLY want to over-ride
        return HttpResponse("You logged in as %s" % identity_url)
    
    def on_cancel(self, request, openid_response):
        return self.show_error(request, self.request_cancelled_message)
    
    def on_failure(self, request, openid_response):
        return self.show_error(
            request, self.failure_message % openid_response.message
        )
    
    def on_setup_needed(self, request, openid_response):
        return self.show_error(request, self.setup_needed_message)
    
    def do_logo(self, request):
        return HttpResponse(
            self.OPENID_LOGO_BASE_64.decode('base64'), mimetype='image/gif'
        )

class LoginConsumer(Consumer):
    redirect_after_login = '/'
    redirect_after_logout = '/'
    
    def on_success(self, *args):
        assert False, 'LoginConsumer must be subclassed before use'
    
    def on_logged_in(self, request, identity_url, openid_response):
        # TODO: Handle ?next= parameter
        return HttpResponseRedirect(self.redirect_after_login)
    
    def on_logged_out(self, request):
        # TODO: Handle ?next= parameter
        return HttpResponseRedirect(self.redirect_after_logout)
    
class SessionConsumer(LoginConsumer):
    """
    When the user logs in, save their OpenID in the session. This can handle 
    multiple OpenIDs being signed in at the same time.
    """
    session_key = 'openids'
    
    def on_success(self, request, identity_url, openid_response):
        if 'openids' not in request.session.keys():
            request.session[self.session_key] = []
        # Eliminate any duplicates
        request.session[self.session_key] = [
            o for o in request.session[self.session_key] 
            if o.openid != identity_url
        ]
        request.session[self.session_key].append(
            OpenID.from_openid_response(openid_response)
        )
        request.session.modified = True
        return self.on_logged_in(request, identity_url, openid_response)
    
    def do_logout(self, request):
        openid = request.GET.get('openid', '').strip()
        if openid:
            # Just sign out that one
            request.session[self.session_key] = [
                o for o in request.session[self.session_key] 
                if o.openid != openid
            ]
        else:
            # Sign out ALL openids
            request.session[self.session_key] = []
        request.session.modified = True
        return self.on_logged_out(request)
    
    # This class doubles up as middleware
    def process_request(self, request):
        request.openid = None
        request.openids = []
        if self.session_key in request.session:
            try:
                request.openid = request.session[self.session_key][0]
            except IndexError:
                request.openid = None
            request.openids = request.session[self.session_key]

class CookieConsumer(CookieUserSessionMixin, LoginConsumer):
    """
    When the user logs in, save their OpenID details in a signed cookie. To 
    avoid cookies getting too big, this endpoint only stores the most 
    recently signed in OpenID; if you want multiple OpenIDs signed in at once
    you should use the SessionConsumer instead.
    """
    cookie_key = 'openid'
    cookie_max_age = None
    cookie_expires = None
    cookie_path = '/'
    cookie_domain = None
    cookie_secure = None
    
    secret_key = None # If none, uses django.conf.settings.SECRET_KEY
    
    def set_cookie(self, request, response, cookie_value):
        response.set_cookie(
            key = self.cookie_key,
            value = cookie_value,
            max_age = self.cookie_max_age,
            expires = self.cookie_expires,
            path = self.cookie_path,
            domain = self.cookie_domain,
            secure = self.cookie_secure,
        )
    
    def delete_cookie(self, response):
        response.delete_cookie(
            self.cookie_key, self.cookie_path, self.cookie_domain
        )
    
    def on_success(self, request, identity_url, openid_response):
        openid = OpenID.from_openid_response(openid_response)
        response = self.on_logged_in(request, identity_url, openid_response)
        self.set_cookie(
            request, response, signed.dumps(
                openid, self.secret_key, compress = True
            )
        )
        return response
    
    def do_logout(self, request):
        response = self.on_logged_out(request)
        self.delete_cookie(response)
        return response
    
    def do_debug(self, request):
        if not settings.DEBUG:
            raise Http404
        if self.cookie_key in request.COOKIES:
            obj = signed.loads(
                request.COOKIES[self.cookie_key], self.secret_key
            )
            assert False, (obj, obj.__dict__)
        assert False, 'no cookie named %s' % self.cookie_key
    
    # This class doubles up as middleware
    def process_request(self, request):
        self._cookie_needs_deleting = False
        request.openid = None
        request.openids = []
        cookie_value = request.COOKIES.get(self.cookie_key, '')
        if cookie_value:
            try:
                request.openid = signed.loads(cookie_value, self.secret_key)
                request.openids = [request.openid]
            except ValueError: # Signature failed
                self._cookie_needs_deleting = True
    
    def process_response(self, request, response):
        if getattr(self, '_cookie_needs_deleting', False):
            self.delete_cookie(response)
        return response

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
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.shortcuts import render_to_response
from openid.consumer import consumer
from openid.consumer.discover import DiscoveryFailure
from openid.yadis import xri
from django_openid.models import DjangoOpenIDStore
from django_openid.utils import OpenID, Router
from django_openid import signed
from django_openid.response import TemplateResponse

class SessionPersist(object):
    def get_user_session(self, request):
        return request.session
    
    def set_user_session(self, request, response, user_session):
        pass

class CookiePersist(object):
    """
    Use this if you are avoiding Django's session support entirely.
    """
    cookie_user_session_key = 'o_user_session'
    cookie_user_session_path = '/'
    cookie_user_session_domain = None
    cookie_user_session_secure = None
    
    def get_user_session(self, request):
        try:
            user_session = signed.loads(
                request.COOKIES.get(self.cookie_user_session_key, '')
            )
        except ValueError:
            user_session = {}
        return user_session
    
    def set_user_session(self, request, response, user_session):
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
    """
    This endpoint can take a user through the most basic OpenID flow, starting
    with an "enter your OpenID" form, dealing with the redirect to the user's 
    provider and calling self.on_success(...) once they've successfully 
    authenticated. You should subclass this and provide your own on_success 
    method, or use CookieConsumer or SessionConsumer if you just want to 
    persist their OpenID in some way.
    """
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
    
    salt_next = 'salt-next-token' # Adds extra saltiness to the ?next= salt
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
    
    urlname_pattern = 'openid-%s'
    
    def __init__(self, persist_class=CookiePersist):
        self.persist = persist_class()
    
    def sign_next(self, url):
        return signed.dumps(url, extra_salt = self.salt_next)
    
    def render(self, request, template, context=None):
        context = context or {}
        context['base_template'] = self.base_template
        return TemplateResponse(request, template, context)
    
    def get_urlpatterns(self):
        # Default behaviour is to introspect self for do_* methods
        from django.conf.urls.defaults import url 
        urlpatterns = []
        for method in dir(self):
            if method.startswith('do_'):
                callback = getattr(self, method)
                name = method.replace('do_', '')
                urlname = self.urlname_pattern % name
                urlregex = getattr(callback, 'urlregex', '^%s/$' % name)
                urlpatterns.append(
                    url(urlregex, callback, name=urlname)
                )
        return urlpatterns
    
    def get_urls(self):
        # In Django 1.1 and later you can hook this in to your urlconf
        from django.conf.urls.defaults import patterns
        return patterns('', *self.get_urlpatterns())
    
    def urls(self):
        return self.get_urls()
    urls = property(urls)
    
    def __call__(self, request, rest_of_url=''):
        if not request.path.endswith('/'):
            return HttpResponseRedirect(request.path + '/')
        router = Router(*self.get_urlpatterns())
        return router(request, path_override = rest_of_url)

    def do_index(self, request, extra_message=None):
        return self.do_login(request, extra_message)
    do_index.urlregex = '^$'
    
    def show_login(self, request, message=None):
        try:
            next = signed.loads(
                request.REQUEST.get('next', ''), extra_salt=self.salt_next
            )
        except ValueError:
            next = ''
        return self.render(request, self.login_template, {
            'action': request.path,
            'logo': self.logo_path or (request.path + 'logo/'),
            'message': message,
            'next': next and request.REQUEST.get('next', '') or None,
        })
    
    def show_error(self, request, message, exception=None):
        return self.render(request, self.error_template, {
            'message': message,
            'exception': exception,
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
    
    def get_on_complete_url(self, request, on_complete_url=None):
        "Derives an appropriate on_complete_url from the request"
        on_complete_url = on_complete_url or self.on_complete_url or \
            (request.path + 'complete/')
        on_complete_url = self.ensure_absolute_url(request, on_complete_url)
        try:
            next = signed.loads(
                request.POST.get('next', ''), extra_salt=self.salt_next
            )
        except ValueError:
            return on_complete_url
        
        if '?' not in on_complete_url:
            on_complete_url += '?next=' + self.sign_next(next)
        else:
            on_complete_url += '&next=' + self.sign_next(next)
        return on_complete_url
    
    def get_trust_root(self, request, trust_root=None):
        "Derives an appropriate trust_root from the request"
        trust_root = trust_root or self.trust_root or \
            request.build_absolute_uri()
        return self.ensure_absolute_url(
            request, trust_root
        )
    
    def do_login(self, request, extra_message=None):
        if request.method == 'GET':
            return self.show_login(request, extra_message)
        
        user_url = request.POST.get('openid_url', None)
        if not user_url:
            return self.show_login(request, self.openid_required_message)
        
        return self.start_openid_process(request, user_url)
    
    def is_xri(self, user_url):
        return xri.identifierScheme(user_url) == 'XRI'
    
    def start_openid_process(
            self, request, user_url, on_complete_url=None, trust_root=None
        ):
        if self.is_xri(user_url) and not self.xri_enabled:
            return self.show_login(request, self.xri_disabled_message)
        
        user_session = self.persist.get_user_session(request)
        
        try:
            auth_request = self.get_consumer(
                request, user_session
            ).begin(user_url)
        except DiscoveryFailure, e:
            return self.show_error(request, self.openid_invalid_message, e)
        
        self.add_extension_args(request, auth_request)
        
        trust_root = self.get_trust_root(request, trust_root)
        on_complete_url = self.get_on_complete_url(request, on_complete_url)
        
        redirect_url = auth_request.redirectURL(trust_root, on_complete_url)
        response = HttpResponseRedirect(redirect_url)
        self.persist.set_user_session(request, response, user_session)
        return response
        
    def dispatch_openid_complete(self, request, handlers):
        user_session = self.persist.get_user_session(request)
        
        openid_response = self.get_consumer(
            request, user_session
        ).complete(
            dict(request.GET.items()),
            request.build_absolute_uri().split('?')[0] # to verify return_to
        )
        if openid_response.status == consumer.SUCCESS:
            response = handlers[consumer.SUCCESS](
                request, openid_response.identity_url, openid_response
            )
        else:
            response = handlers[openid_response.status](
                request, openid_response
            )
        
        self.persist.set_user_session(request, response, user_session)
        
        return response
    
    def do_complete(self, request):
        return self.dispatch_openid_complete(request, {
            consumer.SUCCESS: self.on_success,
            consumer.CANCEL: self.on_cancel,
            consumer.FAILURE: self.on_failure,
            consumer.SETUP_NEEDED: self.on_setup_needed
        })
    
    def do_debug(self, request):
        from django.conf import settings
        if not settings.DEBUG:
            raise Http404
        assert False, 'debug!'
    
    def redirect_if_valid_next(self, request):
        "Logic for checking if a signed ?next= token is included in request"
        try:
            next = signed.loads(
                request.REQUEST.get('next', ''), extra_salt=self.salt_next
            )
            return HttpResponseRedirect(next)
        except ValueError:
            return None
    
    def on_success(self, request, identity_url, openid_response):
        response = self.redirect_if_valid_next(request)
        if not response:
            response = self.show_message(
                request, 'Logged in', "You logged in as %s" % identity_url
            )
        return response
    
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
    
    def ensure_absolute_url(self, request, url):
        if not (url.startswith('http://') or url.startswith('https://')):
            url = request.build_absolute_uri(url)
        return url

class LoginConsumer(Consumer):
    redirect_after_login = '/'
    redirect_after_logout = '/'
    
    def persist_openid(self, request, response, openid_object):
        assert False, 'LoginConsumer must be subclassed before use'
    
    def on_success(self, request, identity_url, openid_response):
        openid_object = OpenID.from_openid_response(openid_response)
        response = self.on_logged_in(request, identity_url, openid_response)
        self.persist_openid(request, response, openid_object)
        return response
    
    def on_logged_in(self, request, identity_url, openid_response):
        response = self.redirect_if_valid_next(request)
        if not response:
            response = HttpResponseRedirect(self.redirect_after_login)
        return response
    
    def on_logged_out(self, request):
        response = self.redirect_if_valid_next(request)
        if not response:
            response = HttpResponseRedirect(self.redirect_after_logout)
        return response
    
class SessionConsumer(LoginConsumer):
    """
    When the user logs in, save their OpenID in the session. This can handle 
    multiple OpenIDs being signed in at the same time.
    """
    session_key = 'openids'
    
    def __init__(self):
        return super(SessionConsumer, self).__init__(SessionPersist)
    
    def persist_openid(self, request, response, openid_object):
        if self.session_key not in request.session.keys():
            request.session[self.session_key] = []
        # Eliminate any duplicates
        request.session[self.session_key] = [
            o for o in request.session[self.session_key] 
            if o.openid != openid_object.openid
        ]
        request.session[self.session_key].append(openid_object)
        request.session.modified = True
    
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

class CookieConsumer(LoginConsumer):
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
    
    extra_salt = 'cookie-consumer'
    
    def delete_cookie(self, response):
        response.delete_cookie(
            self.cookie_key, self.cookie_path, self.cookie_domain
        )
    
    def persist_openid(self, request, response, openid_object):
        response.set_cookie(
            key = self.cookie_key,
            value = signed.dumps(
                openid_object, compress = True, extra_salt = self.extra_salt
            ),
            max_age = self.cookie_max_age,
            expires = self.cookie_expires,
            path = self.cookie_path,
            domain = self.cookie_domain,
            secure = self.cookie_secure,
        )
    
    def do_logout(self, request):
        response = self.on_logged_out(request)
        self.delete_cookie(response)
        return response
    
    def do_debug(self, request):
        from django.conf import settings
        if not settings.DEBUG:
            raise Http404
        if self.cookie_key in request.COOKIES:
            obj = signed.loads(
                request.COOKIES[self.cookie_key], extra_salt = self.extra_salt
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
                request.openid = signed.loads(
                    cookie_value, extra_salt = self.extra_salt
                )
                request.openids = [request.openid]
            except ValueError: # Signature failed
                self._cookie_needs_deleting = True
    
    def process_response(self, request, response):
        if getattr(self, '_cookie_needs_deleting', False):
            self.delete_cookie(response)
        return response

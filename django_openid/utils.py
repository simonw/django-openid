from openid.extensions import sreg
from openid.yadis import xri
import datetime

hex_to_int = lambda s: int(s, 16)
int_to_hex = lambda i: hex(i).replace('0x', '').lower().replace('l', '')

class OpenID:
    def __init__(self, openid, issued, sreg=None):
        self.openid = openid
        self.issued = issued # datetime (used to be int(time.time()))
        self.sreg = sreg or {}
    
    def is_iname(self):
        return xri.identifierScheme(self.openid) == 'XRI'
    
    def __repr__(self):
        return '<OpenID: %s>' % self.openid
    
    def __unicode__(self):
        return self.openid
    
    @classmethod
    def from_openid_response(cls, openid_response):
        return cls(
            openid = openid_response.identity_url,
            issued = datetime.datetime.now(),
            sreg = sreg.SRegResponse.fromSuccessResponse(openid_response),
        )

"""
Convenient wrapper around Django's urlresolvers, allowing them to be used 
from normal application code.

from django.http import HttpResponse
from django_openid.request_factory import RequestFactory
from django.conf.urls.defaults import url
router = Router(
    url('^foo/$', lambda r: HttpResponse('foo'), name='foo'),
    url('^bar/$', lambda r: HttpResponse('bar'), name='bar')
)
rf = RequestFactory()
print router(rf.get('/bar/'))
"""

from django.conf.urls.defaults import patterns
from django.core import urlresolvers

class Router(object):
    def __init__(self, *urlpairs):
        self.urlpatterns = patterns('', *urlpairs)
        # for 1.0 compatibility we pass in None for urlconf_name and then
        # modify the _urlconf_module to make self hack as if its the module.
        self.resolver = urlresolvers.RegexURLResolver(r'^/', None)
        self.resolver._urlconf_module = self
    
    def handle(self, request, path_override=None):
        if path_override is not None:
            path = path_override
        else:
            path = request.path_info
        path = '/' + path # Or it doesn't work
        callback, callback_args, callback_kwargs = self.resolver.resolve(path)
        return callback(request, *callback_args, **callback_kwargs)
    
    def __call__(self, request, path_override=None):
        return self.handle(request, path_override)

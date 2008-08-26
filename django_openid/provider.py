from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.shortcuts import render_to_response

from openid.server.server import Server

from django_openid.models import DjangoOpenIDStore

class OpenIDServer(object):
    """
    The default OpenID server, designed to be subclassed.
    """
    this_is_a_server_template = 'django_openid/this_is_an_openid_server.html'
    landing_page_template = 'django_openid/landing_page.html'
    error_template = 'django_openid/error.html'
    
    not_your_openid_message = 'You are signed in but do not own that OpenID'
    
    def get_server(self, request):
        return Server(DjangoOpenIDStore())
    
    def user_is_logged_in(self, request):
        return False
    
    def openid_is_authorized(self, request, openid, trust_root):
        return self.user_owns_openid(request, openid) \
            and self.user_trusts_root(request, openid, trust_root)
    
    def user_owns_openid(self, request, openid):
        return False
    
    def user_trusts_root(self, request, openid, trust_root):
        # Over-ride this if you want users to manage trust roots
        return True
    
    def server_response(self, request, oresponse):
        webresponse = self.get_server(request).encodeResponse(oresponse)
        response = HttpResponse(webresponse.body)
        response.status_code = webresponse.code
        for key, value in webresponse.headers.items():
            response[key] = value
        return response
    
    def show_landing_page(self, request, orequest):
        return render_to_response(self.landing_page_template, {
            'identity_url': orequest.identity,
        })
    
    def show_error(self, request, message):
        return render_to_response(self.error_template, {
            'message': message,
        })
    
    def show_decide(self, request, orequest):
        # If user is logged in, ask if they want to trust this trust_root
        # If they are NOT logged in, show the landing page:
        if not self.user_is_logged_in(request):
            return self.show_landing_page(request, orequest)
        
        # Check that the user owns the requested identity
        if not self.user_owns_openid(request, orequest.identity):
            return self.show_error(request, self.not_your_openid_message)
        
        # They are logged in - ask if they want to trust this root
        return render_to_response('decide.html', {
            'title': 'Trust this site?',
            'trust_root': orequest.trust_root,
            'identity': orequest.identity,
            # Hidden form field:
            'orequest': pickle_compress_sign(orequest),
        })
    
    def __call__(self, request):
        querydict = dict(request.REQUEST.items())
        orequest = self.get_server(request).decodeRequest(querydict)
        if not orequest:
            return self.show_this_is_an_openid_server(request)
        
        if orequest.mode in ("checkid_immediate", "checkid_setup"):
            if self.openid_is_authorized(
                    request, orequest.identity, orequest.trust_root
                ):
                oresponse = orequest.answer(True)
            elif orequest.immediate:
                oresponse = orequest.answer(
                    False, request.build_absolute_uri()
                )
            else:
                return self.show_decide(request, orequest)
        else:
            oresponse = self.get_server(request).handleRequest(orequest)
        return self.server_response(request, oresponse)
    
    def show_this_is_an_openid_server(self, request):
        return render_to_response(self.this_is_a_server_template)
    
    
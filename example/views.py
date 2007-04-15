from django.http import HttpResponse

from pprint import pformat
from django.utils.html import escape

def index(request):
    s = """
    <p>OpenID is <pre>%s</pre>.</p>
    <p><a href="/openid/">Sign in with OpenID</a></p><pre>
    """ % escape(pformat(request.openid.__dict__.items()))
    s += escape(pformat(request.session._session))
    s += '\n\n\n'
    s += escape(pformat(request.META))
    return HttpResponse(s)

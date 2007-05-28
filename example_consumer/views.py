from django.http import HttpResponse

from pprint import pformat
from django.utils.html import escape

def index(request):
    s = []
    if request.openid:
        s.append('<p>You are signed in as <strong>%s</strong>' % escape(
            str(request.openid)
        ))
        
        if request.openid.is_iname:
            s.append(' (an i-name)')
        s.append('</p>')
        
        if request.openid.sreg:
            s.append('<p>sreg data: %s</p>' % escape(str(request.openid.sreg)))
        
        if len(request.openids) > 1:
            s.append('<p>Also signed in as %s</p>' % ', '.join([
                escape(str(o)) for o in request.openids[:-1]
            ]))

    s.append('<a href="/openid/">Sign in with OpenID</a>')
    s.append(' | <a href="/openid/with-sreg/">')
    s.append('Sign in with OpenID using simple registration</a>')
    s.append(' | <a href="/openid/?next=/next-works/">')
    s.append('Sign in with OpenID, testing ?next= param</a>')
    
    if request.openid:
        s.append(' | <a href="/openid/signout/">Sign out</a>')
    
    s.append('</p>')
    return HttpResponse('\n'.join(s))

def next_works(request):
    return HttpResponse('?next= bit works. <a href="/">Home</a>')
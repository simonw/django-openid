from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.shortcuts import render_to_response as render
from django.template import RequestContext
from django.conf import settings

import md5, time
from openid.consumer.consumer import Consumer, \
    SUCCESS, CANCEL, FAILURE, SETUP_NEEDED
from openid.consumer.discover import DiscoveryFailure
from util import OpenID, DjangoOpenIDStore, from_openid_response

from django.utils.html import escape

def get_url_host(request):
    if request.is_secure():
        protocol = 'https'
    else:
        protocol = 'http'
    host = escape(request.META['HTTP_HOST'])
    return '%s://%s' % (protocol, host)

def get_full_url(request):
    if request.is_secure():
        protocol = 'https'
    else:
        protocol = 'http'
    host = escape(request.META['HTTP_HOST'])
    return get_url_host(request) + request.get_full_path()

def is_valid_after_url(after):
    # When we allow this:
    #   /openid/?after=/welcome/
    # For security reasons we want to restrict the after= bit to being a local 
    # path, not a complete URL.
    if not after.startswith('/'):
        return False
    if '://' in after:
        return False
    for c in after:
        if c.isspace():
            return False
    return True

def begin(request, sreg=None, extension_args=None):
    extension_args = extension_args or {}
    if sreg:
        extension_args['sreg.optional'] = sreg
    trust_root = getattr(
        settings, 'OPENID_TRUST_ROOT', get_url_host(request) + '/'
    )
    redirect_to = getattr(
        settings, 'OPENID_REDIRECT_TO',
        # If not explicitly set, assume current URL with complete/ appended
        get_full_url(request).split('?')[0] + 'complete/'
    )
    
    if request.GET.get('after') and is_valid_after_url(request.GET['after']):
        if '?' in redirect_to:
            join = '&'
        else:
            join = '?'
        redirect_to += join + 'after=' + urllib.urlencode(request.GET['after'])
    
    user_url = request.POST.get('openid_url', None)    
    if not user_url:
        return render('openid_signin.html')
    
    consumer = Consumer(request.session, DjangoOpenIDStore())
    try:
        auth_request = consumer.begin(user_url)
    except DiscoveryFailure:
        raise Http404, "Discovery failure"
    
    # Add extension args (for things like simple registration)
    for name, value in extension_args.items():
        namespace, key = name.split('.', 1)
        auth_request.addExtensionArg(namespace, key, value)
    
    redirect_url = auth_request.redirectURL(trust_root, redirect_to)
    return HttpResponseRedirect(redirect_url)

def complete(request):
    consumer = Consumer(request.session, DjangoOpenIDStore())
    openid_response = consumer.complete(dict(request.GET.items()))
    if openid_response.status == SUCCESS:
        return success(request, openid_response.identity_url, openid_response)
    elif openid_response.status == CANCEL:
        return failure(request, 'The request was cancelled')
    elif openid_response.status == FAILURE:
        return failure(request, openid_response.message)
    elif openid_response.status == SETUP_NEEDED:
        return failure(request, 'Setup needed')
    else:
        assert False, "Bad openid status: %s" % openid_response.status

def success(request, identity_url, openid_response):
    if 'openids' not in request.session.keys():
        request.session['openids'] = []
    
    # Eliminate any duplicates
    request.session['openids'] = [
        o for o in request.session['openids'] if o.openid != identity_url
    ]
    request.session['openids'].append(from_openid_response(openid_response))
    
    after = request.GET.get('after', '').strip()
    if not after or not is_valid_after_url(after):
        after = getattr(settings, 'OPENID_REDIRECT_AFTER', '/')
    
    return HttpResponseRedirect(after)

def failure(request, message):
    return render('openid_failure.html', {
        'message': message
    }) # , context_instance = RequestContext(request))

def signout(request):
    request.session.openids = []
    request.session.openid = None
    next = request.GET.get('next', '/')
    return HttpResponseRedirect(next)

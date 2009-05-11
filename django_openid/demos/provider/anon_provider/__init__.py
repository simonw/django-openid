from django_openid.provider import Provider
from django.shortcuts import render_to_response as render

class AnonProvider(Provider):
    def user_is_logged_in(self, *args):
        return True
    
    def user_owns_openid(self, *args):
        return True
    
    def user_trusts_root(self, *args):
        return True

def openid_page(request, slug):
    return render('openid_page.html', {
        'slug': slug,
        'full_url': request.build_absolute_uri(),
        'server_url': request.build_absolute_uri('/server/'),
    })
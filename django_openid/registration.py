from django.http import HttpResponseRedirect

from django_openid.auth import AuthConsumer
from django_openid.utils import OpenID
from django_openid import forms

from openid.consumer import consumer

import urlparse

class RegistrationConsumer(AuthConsumer):
    already_signed_in_message = 'You are already signed in to this site'
    unknown_openid_message = \
        'That OpenID is not recognised. Would you like to create an account?'
    registration_complete_message = 'Your account has been created'
    
    register_template = 'django_openid/register.html'
    
    after_registration_url = None # None means "show a message instead"
    
    # Registration options
    validate_email_address = True
    reserved_usernames = ['security', 'info', 'admin']
    
    # sreg
    sreg = ['nickname', 'email', 'fullname']
    
    RegistrationForm = forms.RegistrationFormPasswordConfirm
    
    def save_form(self, form):
        user = form.save()
        return user
    
    def get_registration_form_class(self, request):
        return self.RegistrationForm
    
    def show_i_have_logged_you_in(self, request):
        return self.show_message(
            request, 'You are logged in',
            'You already have an account for that OpenID. ' + 
            'You are now logged in.'
        )
    
    def do_register_complete(self, request):
        
        def on_success(request, identity_url, openid_response):
            # We need to behave differently from the default AuthConsumer
            # success behaviour. For simplicity, we do the following:
            # 1. "Log them in" as that OpenID i.e. stash it in the session
            # 2. If it's already associated with an account, log them in as 
            #    that account and show a message.
            # 2. If NOT already associated, redirect back to /register/ again
            openid_object = OpenID.from_openid_response(openid_response)
            matches = self.lookup_openid(request, identity_url)
            if matches:
                # Log them in and show the message
                self.log_in_user(request, matches[0])
                response = self.show_i_have_logged_you_in(request)
            else:
                response = HttpResponseRedirect(urlparse.urljoin(
                    request.path, '../register/'
                ))
            self.persist_openid(request, response, openid_object)
            return response
        
        return self.dispatch_openid_complete(request, {
            consumer.SUCCESS: on_success,
            consumer.CANCEL: 
                lambda request, openid_response: self.do_register(request, 
                    message = self.request_cancelled_message
                ),
            consumer.FAILURE: 
                lambda request, openid_response: self.do_register(request, 
                    message = self.failure_message % openid_response.message
                ),
            consumer.SETUP_NEEDED: 
                lambda request, openid_response: self.do_register(request, 
                    message = self.setup_needed_message
                ),
        })
    
    def on_registration_complete(self, request):
        if self.after_registration_url:
            return HttpResponseRedirect(self.after_registration_url)
        else:
            return self.show_message(
                request, 'Registration complete', 
                self.registration_complete_message
            )
    
    def do_register(self, request, message=None):
        # Show a registration / signup form, provided the user is not 
        # already logged in
        if not request.user.is_anonymous():
            return self.show_already_signed_in(request)
        
        # Spot incoming openid_url authentication requests
        if request.POST.get('openid_url', None):
            return self.start_openid_process(request,
                user_url = request.POST.get('openid_url'),
                on_complete_url = urlparse.urljoin(
                    request.path, '../register_complete/'
                ),
                trust_root = urlparse.urljoin(request.path, '..')
            )
        
        RegistrationForm = self.get_registration_form_class(request)
        
        try:
            openid = request.openid and request.openid.openid or None
        except AttributeError:
            return self.show_error(
                request, 'Add CookieConsumer or similar to your middleware'
            )
        
        if request.method == 'POST':
            # TODO: The user might have entered an OpenID as a starting point,
            # or they might have decided to sign up normally
            form = RegistrationForm(
                request.POST,
                openid = openid,
                reserved_usernames = self.reserved_usernames,
            )
            if form.is_valid():
                user = self.save_form(form) # Also associates the OpenID
                # Now log that new user in
                self.log_in_user(request, user)
                return self.on_registration_complete(request)
        else:
            form = RegistrationForm(
                initial = request.openid and self.initial_from_sreg(
                    request.openid.sreg
                ) or {},
                openid = openid,
                reserved_usernames = self.reserved_usernames,
            )
        
        return self.render(request, self.register_template, {
            'form': form,
            'message': message,
            'openid': request.openid,
            'logo': self.logo_path or (urlparse.urljoin(
                request.path, '../logo/'
            )),
            'no_thanks': self.sign_done(request.path),
            'action': request.path,
        })
    
    def initial_from_sreg(self, sreg):
        "Maps sreg to data for populating registration form"
        fullname = sreg.get('fullname', '')
        first_name, last_name = '', ''
        if fullname:
            bits = fullname.split()
            first_name = bits[0]
            if len(bits) > 1:
                last_name = ' '.join(bits[1:])
        return {
            'username': self.suggest_nickname(sreg.get('nickname', '')),
            'first_name': first_name,
            'last_name': last_name,
            'email': sreg.get('email', ''),
        }
    
    def suggest_nickname(self, nickname):
        "Return a suggested nickname that has not yet been taken"
        from django.contrib.auth.models import User
        if not nickname:
            return ''
        original_nickname = nickname
        suffix = None
        while User.objects.filter(username = nickname).count():
            if suffix is None:
                suffix = 1
            else:
                suffix += 1
            nickname = original_nickname + str(suffix)
        return nickname
    
    def show_unknown_openid(self, request, openid):
        # If the user gets here, they have attempted to log in using an 
        # OpenID BUT it's an OpenID we have never seen before - so show 
        # them the index page but with an additional message
        return self.do_index(request, self.unknown_openid_message)
    
    def show_already_signed_in(self, request):
        return self.show_message(
            request, 'Already signed in', self.already_signed_in_message
        )

from django.http import HttpResponseRedirect
from django.core.mail import send_mail
from django.conf import settings

from django_openid.auth import AuthConsumer
from django_openid.utils import OpenID, int_to_hex, hex_to_int
from django_openid import signed
from django_openid import forms

from openid.consumer import consumer

import urlparse

class RegistrationConsumer(AuthConsumer):
    already_signed_in_message = 'You are already signed in to this site'
    unknown_openid_message = \
        'That OpenID is not recognised. Would you like to create an account?'
    c_already_confirmed_message = 'Your account is already confirmed'
    
    register_template = 'django_openid/register.html'
    set_password_template = 'django_openid/set_password.html'
    confirm_email_template = 'django_openid/register_confirm_email.txt'
    register_email_sent_template = 'django_openid/register_email_sent.html'
    register_complete_template = 'django_openid/register_complete.html'
    
    after_registration_url = None # None means "show a message instead"
    unconfirmed_group = 'Unconfirmed users'
    
    # Registration options
    reserved_usernames = ['security', 'info', 'admin']
    no_duplicate_emails = True    
    confirm_email_addresses = True
    
    confirm_email_from = None # If None, uses settings.DEFAULT_FROM_EMAIL
    confirm_email_subject = 'Confirm your e-mail address'
    confirm_link_secret = None
    confirm_link_salt = 'confirm-link-salt'
    
    # sreg
    sreg = ['nickname', 'email', 'fullname']
    
    RegistrationForm = forms.RegistrationFormPasswordConfirm
    ChangePasswordForm = forms.ChangePasswordForm
    
    def user_is_confirmed(self, user):
        return not self.user_is_unconfirmed(user)
    
    def user_is_unconfirmed(self, user):
        return user.groups.filter(name = self.unconfirmed_group).count()
    
    def mark_user_unconfirmed(self, user):
        from django.contrib.auth.models import Group
        user.is_active = False
        user.save()
        group, _ = Group.objects.get_or_create(name = self.unconfirmed_group)
        user.groups.add(group)
    
    def mark_user_confirmed(self, user):
        user.groups.filter(name = self.unconfirmed_group).delete()
    
    def get_registration_form_class(self, request):
        return self.RegistrationForm
    
    def get_change_password_form_class(self, request):
        return self.ChangePasswordForm
    
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
            return self.render(request, self.register_complete_template)
    
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
                no_duplicate_emails = self.no_duplicate_emails
            )
            if form.is_valid():
                user = self.create_user(request, form.cleaned_data, openid)
                if self.confirm_email_addresses:
                    return self.confirm_email_step(request, user)
                else:
                    self.log_in_user(request, user)
                    return self.on_registration_complete(request)
        else:
            form = RegistrationForm(
                initial = request.openid and self.initial_from_sreg(
                    request.openid.sreg
                ) or {},
                openid = openid,
                reserved_usernames = self.reserved_usernames,
                no_duplicate_emails = self.no_duplicate_emails
            )
        
        return self.render(request, self.register_template, {
            'form': form,
            'message': message,
            'openid': request.openid,
            'logo': self.logo_path or (urlparse.urljoin(
                request.path, '../logo/'
            )),
            'no_thanks': self.sign_next(request.path),
            'action': request.path,
        })
    
    def confirm_email_step(self, request, user):
        self.mark_user_unconfirmed(user)
        self.send_confirm_email(request, user)
        return self.render(request, self.register_email_sent_template, {
            'email': user.email,
        })
    
    def generate_confirm_code(self, user):
        return signed.sign(int_to_hex(user.id), key = (
            self.confirm_link_secret or settings.SECRET_KEY
        ) + self.confirm_link_salt)
    
    def send_confirm_email(self, request, user):
        from_email = self.confirm_email_from or settings.DEFAULT_FROM_EMAIL
        code = self.generate_confirm_code(user)
        path = urlparse.urljoin(request.path, '../c/%s/' % code)
        url = request.build_absolute_uri(path)
        send_mail(
            subject = self.confirm_email_subject,
            message = self.render(request, self.confirm_email_template, {
                'url': url,
                'code': code,
                'user': user,
            }).content,
            from_email = from_email,
            recipient_list = [user.email]
        )
    
    def do_c(self, request, token = ''):
        if not token:
            # TODO: show a form where they can paste in their token?
            raise Http404
        token = token.rstrip('/').encode('utf8')
        try:
            value = signed.unsign(token, key = (
                self.confirm_link_secret or settings.SECRET_KEY
            ) + self.confirm_link_salt)
        except signed.BadSignature:
            return self.show_message(
                request, self.invalid_token_message,
                self.invalid_token_message + ': ' + token
            )
        user_id = hex_to_int(value)
        user = self.lookup_user_by_id(user_id)
        if not user: # Maybe the user was deleted?
            return self.show_error(request, r_user_not_found_message)
        
        # Check user is NOT active but IS in the correct group
        if self.user_is_unconfirmed(user):
            # Confirm them
            user.is_active = True
            user.save()
            self.mark_user_confirmed(user)
            self.log_in_user(request, user)
            return self.on_registration_complete(request)
        else:
            return self.show_error(request, self.c_already_confirmed_message)
    
    do_c.urlregex = '^c/([^/]+)/$'
    
    def create_user(self, request, data, openid=None):
        from django.contrib.auth.models import User
        user = User.objects.create(
            username = data['username'],
            first_name = data.get('first_name', ''),
            last_name = data.get('last_name', ''),
            email = data.get('email', ''),
        )
        # Set OpenID, if one has been associated
        if openid:
            user.openids.create(openid = openid)
        # Set password, if one has been specified
        password = data.get('password')
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save()
        return user
    
    def do_password(self, request):
        "Allow users to set a password on their account"
        if request.user.is_anonymous():
            return self.show_error(request, 'You need to log in first')
        ChangePasswordForm = self.get_change_password_form_class(request)
        if request.method == 'POST':
            form = ChangePasswordForm(request.user, data=request.POST)
            if form.is_valid():
                u = request.user
                u.set_password(form.cleaned_data['password'])
                u.save()
                return self.show_password_has_been_set(request)
        else:
            form = ChangePasswordForm(request.user)
        return self.render(request, self.set_password_template, {
            'form': form,
            'action': request.path,
        })
    
    def show_password_has_been_set(self, request):
        return self.show_message(
            request, 'Password set', 'Your password has been set.'
        )
    
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

from django.http import HttpResponseRedirect as Redirect, Http404
from django_openid import consumer, signed
from django_openid.utils import hex_to_int, int_to_hex
from django.conf import settings
from django.contrib.auth import authenticate
from django.core.mail import send_mail

import hashlib, datetime
from urlparse import urljoin

# TODO: prevent multiple associations of same OpenID

class AuthConsumer(consumer.SessionConsumer):
    """
    An OpenID consumer endpoint that integrates with Django's auth system.
    Uses SessionConsumer rather than CookieConsumer because the auth system
    relies on sessions already.
    """
    after_login_redirect_url = '/'
    
    associations_template = 'django_openid/associations.html'
    login_plus_password_template = 'django_openid/login_plus_password.html'
    recover_template = 'django_openid/recover.html'
    already_logged_in_template = 'django_openid/already_logged_in.html'
    pick_account_template = 'django_openid/pick_account.html'
    show_associate_template = 'django_openid/associate.html'
    recovery_email_template = 'django_openid/recovery_email.txt'
    recovery_expired_template = 'django_openid/recovery_expired.html'
    recovery_complete_template = 'django_openid/recovery_complete.html'
    
    recovery_email_from = None
    recovery_email_subject = 'Recover your account'
    
    password_logins_enabled = True
    account_recovery_enabled = True
    
    need_authenticated_user_message = 'You need to sign in with an ' \
        'existing user account to access this page.'
    csrf_failed_message = 'Invalid submission'
    associate_tampering_message = 'Invalid submission'
    association_deleted_message = '%s has been deleted'
    openid_now_associated_message = \
        'The OpenID "%s" is now associated with your account.'
    bad_password_message = 'Incorrect username or password'
    invalid_token_message = 'Invalid token'
    recovery_email_sent_message = 'Check your mail for further instructions'
    recovery_not_found_message = 'No matching user was found'
    recovery_multiple_found_message = 'Try entering your username instead'
    r_user_not_found_message = 'That user account does not exist'
    
    account_recovery_url = None
    
    associate_salt = 'associate-salt'
    associate_delete_salt = 'associate-delete-salt'
    recovery_link_salt = 'recovery-link-salt'
    recovery_link_secret = None # If None, uses settings.SECRET_KEY
    
    # For generating recovery URLs
    recovery_origin_date = datetime.date(2000, 1, 1)
    recovery_expires_after_days = 3 # Number of days recovery URL is valid for
    
    def show_login(self, request, extra_message=None):
        if request.user.is_authenticated():
            return self.show_already_logged_in(request)
        
        response = super(AuthConsumer, self).show_login(
            request, extra_message
        )
        
        if self.password_logins_enabled:
            response.template_name = self.login_plus_password_template
            response.template_context.update({
                'account_recovery': self.account_recovery_enabled and (
                    self.account_recovery_url or (request.path + 'recover/')
                ),
            })
        return response
    
    def show_already_logged_in(self, request):
        return self.render(request, self.already_logged_in_template) 
    
    def do_login(self, request, extra_message=None):
        if request.method == 'POST' and \
                request.POST.get('username', '').strip():
            # Do a username/password login instead
            user = authenticate(
                username = request.POST.get('username'),
                password = request.POST.get('password')
            )
            if not user:
                return self.show_login(request, self.bad_password_message)
            else:
                self.log_in_user(request, user)
                return self.on_login_complete(request, user, openid=None)
        else:
            return super(AuthConsumer, self).do_login(request, extra_message)
    
    def lookup_openid(self, request, identity_url):
        # Imports lives inside this method so User won't get imported if you 
        # over-ride this in your own sub-class and use something else.
        from django.contrib.auth.models import User
        return list(
            User.objects.filter(openids__openid = identity_url).distinct()
        )
    
    def log_in_user(self, request, user):
        # Remember, openid might be None (after registration with none set)
        from django.contrib.auth import login
        # Nasty but necessary - annotate user and pretend it was the regular 
        # auth backend. This is needed so django.contrib.auth.get_user works:
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(request, user)
    
    def on_login_complete(self, request, user, openid=None):
        response = self.redirect_if_valid_next(request)
        if not response:
            response = Redirect(self.after_login_redirect_url)
        return response
    
    def on_logged_in(self, request, openid, openid_response):
        # Do we recognise their OpenID?
        matches = self.lookup_openid(request, openid)
        # Are they logged in already?
        if request.user.is_authenticated():
            # Did we find their account already? If so, ignore login
            if request.user.id in [u.id for u in matches]:
                response = self.redirect_if_valid_next(request)
                if not response:
                    response = Redirect(self.after_login_redirect_url)
                return response
            else:
                # Offer to associate this OpenID with their account
                return self.show_associate(request, openid)
        if matches:
            # If there's only one match, log them in as that user
            if len(matches) == 1:
                user = matches[0]
                if self.user_can_login(request, user):
                    self.log_in_user(request, user)
                    return self.on_login_complete(request, user, openid)
                else:
                    # User is not allowed to log in for some other reason - 
                    # for example, they have not yet validated their e-mail 
                    # or they have been banned from the site.
                    return self.show_you_cannot_login(request, user, openid)
            # Otherwise, let them to pick which account they want to log in as
            else:
                return self.show_pick_account(request, openid)
        else:
            # We don't know anything about this openid
            return self.show_unknown_openid(request, openid)
    
    def user_can_login(self, request, user):
        "Over-ride for things like user bans or account e-mail validation"
        return user.is_active
    
    def show_pick_account(self, request, openid):
        """
        The user's OpenID is associated with more than one account - ask them
        which one they would like to sign in as
        """
        return self.render(request, self.pick_account_template, {
            'action': urljoin(request.path, '../pick/'),
            'openid': openid,
            'users': self.lookup_openid(request, openid),
        })
    
    def do_pick(self, request):
        # User MUST be logged in with an OpenID and it MUST be associated
        # with the selected account. The error messages in here are a bit 
        # weird, unfortunately.
        if not request.openid:
            return self.show_error(request, 'You should be logged in here')
        users = self.lookup_openid(request, request.openid.openid)
        try:
            user_id = [
                v.split('-')[1] for v in request.POST if v.startswith('user-')
            ][0]
            user = [u for u in users if str(u.id) == user_id][0]
        except IndexError, e:
            return self.show_error(request, "You didn't pick a valid user")
        # OK, log them in
        self.log_in_user(request, user)
        return self.on_login_complete(request, user, request.openid.openid)
    
    def on_logged_out(self, request):
        # After logging out the OpenID, log out the user auth session too
        from django.contrib.auth import logout
        response = super(AuthConsumer, self).on_logged_out(request)
        logout(request)
        return response
    
    def show_unknown_openid(self, request, openid):
        # This can be over-ridden to show a registration form
        return self.show_message(
            request, 'Unknown OpenID', '%s is an unknown OpenID' % openid
        )
    
    def show_you_cannot_login(self, request, user, openid):
        return self.show_message(
            request, 'You cannot log in',
            'You cannot log in with that account'
        )
    
    def show_associate(self, request, openid=None):
        "Screen that offers to associate an OpenID with a user's account"
        if not request.user.is_authenticated():
            return self.need_authenticated_user(request)
        try:
            next = signed.loads(
                request.REQUEST.get('next', ''), extra_salt=self.salt_next
            )
        except ValueError:
            next = ''
        return self.render(request, self.show_associate_template, {
            'action': urljoin(request.path, '../associate/'),
            'user': request.user,
            'specific_openid': openid,
            'next': next and request.REQUEST.get('next', '') or None,
            'openid_token': signed.dumps(
               # Use user.id as part of extra_salt to prevent attackers from
               # creating their own openid_token for use in CSRF attack
               openid, extra_salt = self.associate_salt + str(request.user.id)
            ),
        })
    
    def do_associate(self, request):
        if request.method == 'POST':
            try:
                openid = signed.loads(
                    request.POST.get('openid_token', ''),
                    extra_salt = self.associate_salt + str(request.user.id)
                )
            except signed.BadSignature:
                return self.show_error(request, self.csrf_failed_message)
            # Associate openid with their account, if it isn't already
            if not request.user.openids.filter(openid = openid):
                request.user.openids.create(openid = openid)
            return self.show_associate_done(request, openid)
            
        return self.show_error(request, 'Should POST to here')
    
    def show_associate_done(self, request, openid):
        response = self.redirect_if_valid_next(request)
        if not response:
            response = self.show_message(request, 'Associated', 
                self.openid_now_associated_message % openid
            )
        return response
    
    def need_authenticated_user(self, request):
        return self.show_error(request, self.need_authenticated_user_message)
    
    def do_associations(self, request):
        "Interface for managing your account's associated OpenIDs"
        if not request.user.is_authenticated():
            return self.need_authenticated_user(request)
        message = None
        if request.method == 'POST':
            if 'todelete' in request.POST:
                # Something needs deleting; find out what
                try:
                    todelete = signed.loads(
                        request.POST['todelete'],
                        extra_salt = self.associate_delete_salt
                    )
                    if todelete['user_id'] != request.user.id:
                        message = self.associate_tampering_message
                    else:
                        # It matches! Delete the OpenID relationship
                        request.user.openids.filter(
                            pk = todelete['association_id']
                        ).delete()
                        message = self.association_deleted_message % (
                            todelete['openid']
                        )
                except signed.BadSignature:
                    message = self.associate_tampering_message
        # We construct a button to delete each existing association
        openids = []
        for association in request.user.openids.all():
            openids.append({
                'openid': association.openid,
                'button': signed.dumps({
                    'user_id': request.user.id,
                    'association_id': association.id,
                    'openid': association.openid,
                }, extra_salt = self.associate_delete_salt),
            })
        return self.render(request, self.associations_template, {
            'openids': openids,
            'user': request.user,
            'action': request.path,
            'message': message,
            'action_new': '../',
            'associate_next': self.sign_next(request.path),
        })
    
    def do_recover(self, request, extra_message = None):
        if request.method == 'POST':
            submitted = request.POST.get('recover', '').strip()
            user = None
            if '@' not in submitted: # They entered a username
                user = self.lookup_user_by_username(submitted)
            else: # They entered an e-mail address
                users = self.lookup_users_by_email(submitted)
                if users:
                    if len(users) > 1:
                        extra_message = self.recovery_multiple_found_message
                        user = None
                    else:
                        user = users[0]
            if user:
                self.send_recovery_email(request, user)
                return self.show_message(
                    request, 'E-mail sent', self.recovery_email_sent_message
                )
            else:
                extra_message = self.recovery_not_found_message
        return self.render(request, self.recover_template, {
            'action': request.path,
            'message': extra_message,
        })
    
    def lookup_users_by_email(self, email):
        from django.contrib.auth.models import User
        return list(User.objects.filter(email = email))
    
    def lookup_user_by_username(self, username):
        from django.contrib.auth.models import User
        try:
            return User.objects.get(username = username)
        except User.DoesNotExist:
            return None
    
    def lookup_user_by_id(self, id):
        from django.contrib.auth.models import User
        try:
            return User.objects.get(pk = id)
        except User.DoesNotExist:
            return None
    
    def do_r(self, request, token = ''):
        if not token:
            # TODO: show a form where they can paste in their token?
            raise Http404
        token = token.rstrip('/').encode('utf8')
        try:
            value = signed.unsign(token, key = (
                self.recovery_link_secret or settings.SECRET_KEY
            ) + self.recovery_link_salt)
        except signed.BadSignature:
            return self.show_message(
                request, self.invalid_token_message,
                self.invalid_token_message + ': ' + token
            )
        hex_days, hex_user_id = (value.split('.') + ['', ''])[:2]
        days = hex_to_int(hex_days)
        user_id = hex_to_int(hex_user_id)
        user = self.lookup_user_by_id(user_id)
        if not user: # Maybe the user was deleted?
            return self.show_error(request, r_user_not_found_message)
        
        # Has the token expired?
        now_days = (datetime.date.today() - self.recovery_origin_date).days
        if (now_days - days) > self.recovery_expires_after_days:
            return self.render(request, self.recovery_expired_template, {
                'days': self.recovery_expires_after_days,
                'recover_url': urljoin(request.path, '../../recover/'),
            })
        
        # Token is valid! Log them in as that user and show the recovery page
        self.log_in_user(request, user)
        return self.render(request, self.recovery_complete_template, {
            'change_password_url': urljoin(request.path, '../../password/'),
            'associate_url': urljoin(request.path, '../../associations/'),
            'user': user,
        })
    do_r.urlregex = '^r/([^/]+)/$'
    
    def generate_recovery_code(self, user):
        # Code is {hex-days}.{hex-userid}.{signature}
        days = int_to_hex(
            (datetime.date.today() - self.recovery_origin_date).days
        )
        token = '%s.%s' % (days, int_to_hex(user.id))
        return signed.sign(token, key = (
            self.recovery_link_secret or settings.SECRET_KEY
        ) + self.recovery_link_salt)
    
    def send_recovery_email(self, request, user):
        code = self.generate_recovery_code(user)
        path = urljoin(request.path, '../r/%s/' % code)
        url = request.build_absolute_uri(path)
        email_body = self.render(request, self.recovery_email_template, {
            'url': url,
            'code': code,
            'user': user,
        }).content
        send_mail(
            subject = self.recovery_email_subject,
            message = email_body,
            from_email = self.recovery_email_from or \
                settings.DEFAULT_FROM_EMAIL,
            recipient_list = [user.email]
        )

# Monkey-patch to add openid login form to the Django admin
def make_display_login_form_with_openid(bind_to_me, openid_path):
    "openid_path is the path the OpenID login should submit to, e.g. /openid/"
    from django.contrib.admin.sites import AdminSite
    def display_login_form(request, error_message='', 
            extra_context=None):
        extra_context = extra_context or {}
        extra_context['openid_path'] = openid_path
        return AdminSite.display_login_form(
            bind_to_me, request, error_message, extra_context
        )
    return display_login_form

def monkeypatch_adminsite(admin_site, openid_path = '/openid/'):
    admin_site.display_login_form = make_display_login_form_with_openid(
        admin_site, openid_path
    )


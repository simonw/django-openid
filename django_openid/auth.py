from django.http import HttpResponseRedirect as Redirect
from django_openid import consumer, signed
from django.conf import settings

import urlparse

def display_login_form_openid(bind_to_me, openid_path):
    # Monkey-patch for the admin
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

class AuthConsumer(consumer.SessionConsumer):
    """
    An OpenID consumer endpoint that integrates with Django's auth system.
    Uses SessionConsumer rather than CookieConsumer because the auth system
    relies on sessions already.
    """
    after_login_redirect_url = '/'
    
    associations_template = 'django_openid/associations.html'
    
    need_authenticated_user_message = 'You need to sign in with an ' \
        'existing user account to access this page.'
    csrf_failed_message = 'Invalid submission'
    associate_tampering_message = 'Invalid submission'
    association_deleted_message = '%s has been deleted'
    openid_now_associated_message = \
        'The OpenID "%s" is now associated with your account.'
    
    associate_salt = 'associate-salt'
    associate_delete_salt = 'associate-delete-salt'
    
    def lookup_openid(self, request, identity_url):
        # Imports lives inside this method so User won't get imported if you 
        # over-ride this in your own sub-class and use something else.
        from django.contrib.auth.models import User
        return list(
            User.objects.filter(openids__openid = identity_url).distinct()
        )
    
    def log_in_user(self, request, user, openid):
        from django.contrib.auth import login
        # Nasty but necessary - annotate user and pretend it was the regular 
        # auth backend. This is needed so django.contrib.auth.get_user works:
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        login(request, user)
        return self.on_login_complete(request, user, openid)
    
    def on_login_complete(self, request, user, openid):
        return Redirect(self.after_login_redirect_url)
    
    def already_logged_in(self, request, openid):
        return Redirect(self.after_login_redirect_url)
    
    def on_logged_in(self, request, openid, openid_response):
        # Do we recognise their OpenID?
        matches = self.lookup_openid(request, openid)
        # Are they logged in already?
        if request.user.is_authenticated():
            # Did we find their account already? If so, ignore login
            if request.user.id in [u.id for u in matches]:
                return self.already_logged_in(request, openid)
            else:
                # Offer to associate this OpenID with their account
                return self.show_associate(request, openid)
        if matches:
            # If there's only one match, log them in as that user
            if len(matches) == 1:
                return self.log_in_user(request, matches[0], openid)
            # Otherwise, let them to pick which account they want to log in as
            else:
                return self.show_pick_account(request, openid)
        else:
            # We don't know anything about this openid
            return self.show_unknown_openid(request, openid)
    
    def show_unknown_openid(self, request, openid):
        # This can be over-ridden to show a registration form
        return self.show_message(
            request, 'Unknown OpenID', '%s is an unknown OpenID' % openid
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
        return self.render(request, 'django_openid/associate.html', {
            'action': urlparse.urljoin(request.path, '../associate/'),
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
        return self.show_error(self.need_authenticated_user_message)
    
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
            'associate_next': self.sign_done(request.path),
        })

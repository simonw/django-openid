from django.contrib.auth.models import User
from django import forms

import re

class RegistrationForm(forms.ModelForm):
    no_password_error = 'You must either set a password or attach an OpenID'
    invalid_username_error = 'Usernames must consist of letters and numbers'
    reserved_username_error = 'That username cannot be registered'
    duplicate_email_error = 'That e-mail address is already in use'
    
    username_re = re.compile('^[a-zA-Z0-9]+$')
    
    # Additional required fields (above what the User model says)
    extra_required = ('first_name', 'last_name', 'email')
    
    def __init__(self, *args, **kwargs):
        """
        Accepts openid as optional keyword argument, for password validation.
        Also accepts optional reserved_usernames keyword argument which is a
        list of usernames that should not be registered (e.g. 'security')
        """
        try:
            self.openid = kwargs.pop('openid')
        except KeyError:
            self.openid = None
        try:
            self.reserved_usernames = kwargs.pop('reserved_usernames')
        except KeyError:
            self.reserved_usernames = []
        try:
            self.no_duplicate_emails = kwargs.pop('no_duplicate_emails')
        except KeyError:
            self.no_duplicate_emails = False
        
        # Super's __init__ creates self.fields for us
        super(RegistrationForm, self).__init__(*args, **kwargs)
        # Now we can modify self.fields with our extra required information
        for field in self.extra_required:
            self.fields[field].required = True
    
    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email')
    
    # Password is NOT required as a general rule; we only validate that they 
    # have set a password if an OpenID is not being associated
    password = forms.CharField(
        widget = forms.PasswordInput,
        required = False
    )
    
    def clean_username(self):
        username = self.cleaned_data.get('username', '')
        if not self.username_re.match(username):
            raise forms.ValidationError, self.invalid_username_error
        if username in self.reserved_usernames:
            raise forms.ValidationError, self.reserved_username_error
        return username
    
    def clean_password(self):
        "Password is only required if no OpenID was specified"
        password = self.cleaned_data.get('password', '')
        if not self.openid and not password:
            raise forms.ValidationError, self.no_password_error
        return password
    
    def clean_email(self):
        email = self.cleaned_data.get('email', '')
        if self.no_duplicate_emails and User.objects.filter(
            email = email
        ).count() > 0:
            raise forms.ValidationError, self.duplicate_email_error
        return email

class RegistrationFormPasswordConfirm(RegistrationForm):
    password_mismatch_error = 'Your passwords do not match'
    
    password2 = forms.CharField(
        widget = forms.PasswordInput,
        required = False,
        label = "Confirm password"
    )
    
    def clean_password2(self):
        password = self.cleaned_data.get('password', '')
        password2 = self.cleaned_data.get('password2', '')
        if password and (password != password2):
            raise forms.ValidationError, self.password_mismatch_error
        return password2

class ChangePasswordForm(forms.Form):
    password = forms.CharField(
        widget = forms.PasswordInput,
        required = True
    )
    password2 = forms.CharField(
        widget = forms.PasswordInput,
        required = True,
        label = 'Confirm password'
    )
    password_mismatch_error = 'Your passwords do not match'
    
    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(ChangePasswordForm, self).__init__(*args, **kwargs)
    
    def clean_password2(self):
        password = self.cleaned_data.get('password', '')
        password2 = self.cleaned_data.get('password2', '')
        if password and (password != password2):
            raise forms.ValidationError, self.password_mismatch_error
        return password2

class ChangePasswordVerifyOldForm(ChangePasswordForm):
    """
    Use this if you want the user to enter their old password first
    
    Careful though... if hte user has just recovered their account, they
    should be able to reset their password without having to enter the old
    one. This case is not currently handled.
    """
    password_incorrect_error = 'Your password is incorrect'
    
    def __init__(self, *args, **kwargs):
        super(ChangePasswordVerifyOldForm, self).__init__(*args, **kwargs)
        if self.user.has_usable_password() and self.user.password:
            # Only ask for their old password if they have set it already
            self.fields['old_password'] = forms.CharField(
                widget = forms.PasswordInput,
                required = True
            )
    
    def clean_old_password(self):
        password = self.cleaned_data.get('old_password', '')
        if not self.user.check_password(password):
            raise forms.ValidationError, self.password_incorrect_error

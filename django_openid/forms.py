from django.contrib.auth.models import User
from django import forms

import re

class RegistrationForm(forms.ModelForm):
    no_password_error = 'You must either set a password or attach an OpenID'
    invalid_username_error = 'Usernames must consist of letters and numbers'
    reserved_username_error = 'That username cannot be registered'
    
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
    
    
    def save(self):
        user = User.objects.create(
            username = self.cleaned_data['username'],
            first_name = self.cleaned_data.get('first_name', ''),
            last_name = self.cleaned_data.get('last_name', ''),
            email = self.cleaned_data.get('email', ''),
        )
        # Set OpenID, if one has been associated
        if self.openid:
            user.openids.create(openid = self.openid)
        # Set password, if one has been specified
        password = self.cleaned_data.get('password')
        if password:
            user.set_password(password)
            user.save()
        return user

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

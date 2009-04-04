from django.db import models
from django.conf import settings
from django.utils.hashcompat import md5_constructor
from openid.store.interface import OpenIDStore
import openid.store
from openid.association import Association as OIDAssociation
import time, base64

class Nonce(models.Model):
    server_url = models.CharField(max_length=255)
    timestamp = models.IntegerField()
    salt = models.CharField(max_length=40)
    
    def __unicode__(self):
        return u"Nonce: %s for %s" % (self.salt, self.server_url)

class Association(models.Model):
    server_url = models.TextField(max_length=2047)
    handle = models.CharField(max_length=255)
    secret = models.TextField(max_length=255) # Stored base64 encoded
    issued = models.IntegerField()
    lifetime = models.IntegerField()
    assoc_type = models.TextField(max_length=64)
    
    def __unicode__(self):
        return u"Association: %s, %s" % (self.server_url, self.handle)

class DjangoOpenIDStore(OpenIDStore):
    """
    The Python openid library needs an OpenIDStore subclass to persist data 
    related to OpenID authentications. This one uses our Django models.
    """
    
    def storeAssociation(self, server_url, association):
        assoc = Association(
            server_url = server_url,
            handle = association.handle,
            secret = base64.encodestring(association.secret),
            issued = association.issued,
            lifetime = association.issued,
            assoc_type = association.assoc_type
        )
        assoc.save()
    
    def getAssociation(self, server_url, handle=None):
        assocs = []
        if handle is not None:
            assocs = Association.objects.filter(
                server_url = server_url, handle = handle
            )
        else:
            assocs = Association.objects.filter(
                server_url = server_url
            )
        if not assocs:
            return None
        associations = []
        for assoc in assocs:
            association = OIDAssociation(
                assoc.handle, base64.decodestring(assoc.secret), assoc.issued,
                assoc.lifetime, assoc.assoc_type
            )
            if association.getExpiresIn() == 0:
                self.removeAssociation(server_url, assoc.handle)
            else:
                associations.append((association.issued, association))
        if not associations:
            return None
        return associations[-1][1]
    
    def removeAssociation(self, server_url, handle):
        assocs = list(Association.objects.filter(
            server_url = server_url, handle = handle
        ))
        assocs_exist = len(assocs) > 0
        for assoc in assocs:
            assoc.delete()
        return assocs_exist
    
    def useNonce(self, server_url, timestamp, salt):
        # Has nonce expired?
        if abs(timestamp - time.time()) > openid.store.nonce.SKEW:
            return False
        try:
            nonce = Nonce.objects.get(
                server_url__exact = server_url,
                timestamp__exact = timestamp,
                salt__exact = salt
            )
        except Nonce.DoesNotExist:
            nonce = Nonce.objects.create(
                server_url = server_url,
                timestamp = timestamp,
                salt = salt
            )
            return True
        nonce.delete()
        return False
    
    def cleanupNonce(self):
        Nonce.objects.filter(
            timestamp__lt = (int(time.time()) - nonce.SKEW)
        ).delete()
    
    def cleaupAssociations(self):
        Association.objects.extra(
            where=['issued + lifetimeint < (%s)' % time.time()]
        ).delete()
    
    def getAuthKey(self):
        # Use first AUTH_KEY_LEN characters of md5 hash of SECRET_KEY
        return md5_constructor.new(settings.SECRET_KEY).hexdigest()[:self.AUTH_KEY_LEN]
    
    def isDumb(self):
        return False

# Only include table for User->OpenID associations if User model is installed
user_model = models.get_model('auth', 'User')
if user_model and user_model._meta.installed:
    class UserOpenidAssociation(models.Model):
        "Auth integration - lets you associate 1+ OpenIDs with a User"
        user = models.ForeignKey('auth.User', related_name = 'openids')
        openid = models.CharField(max_length = 255)
        created = models.DateTimeField(auto_now_add = True)
        
        def __unicode__(self):
            return u'%s can log in with %s' % (self.user, self.openid)

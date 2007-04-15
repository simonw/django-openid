from django.db import models

class Nonce(models.Model):
    nonce = models.CharField(maxlength=8)
    expires = models.IntegerField()
    def __str__(self):
        return "Nonce: %s" % self.nonce

class Association(models.Model):
    server_url = models.TextField(maxlength=2047)
    handle = models.CharField(maxlength=255)
    secret = models.TextField(maxlength=255) # Stored base64 encoded
    issued = models.IntegerField()
    lifetime = models.IntegerField()
    assoc_type = models.TextField(maxlength=64)
    def __str__(self):
        return "Association: %s, %s" % (self.server_url, self.handle)

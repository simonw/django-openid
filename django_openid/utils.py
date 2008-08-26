from openid.yadis import xri
import datetime, pickle, zlib, base64, hashlib
from django.conf import settings

class OpenID:
    def __init__(self, openid, issued, sreg=None):
        self.openid = openid
        self.issued = issued # datetime (used to be int(time.time()))
        self.sreg = sreg or {}
    
    def is_iname(self):
        return xri.identifierScheme(self.openid) == 'XRI'
    
    def __repr__(self):
        return '<OpenID: %s>' % self.openid
    
    def __unicode__(self):
        return self.openid
    
    @classmethod
    def from_openid_response(cls, openid_response):
        return cls(
            openid = openid_response.identity_url,
            issued = datetime.datetime.now(),
            sreg = openid_response.extensionResponse('sreg', False)
        )

# Functions for converting an object in to a signed base64 urlsafe string
def encode_object(obj, secret=None):
    "Returns URL-safe, sha1 signed base64 compressed pickle"
    pickled = pickle.dumps(obj)
    compressed = zlib.compress(pickled)
    base64d = base64.urlsafe_b64encode(compressed)
    sig = hashlib.sha1(base64d + (secret or settings.SECRET_KEY)).hexdigest()
    return base64d + ':' + sig

def decode_object(s, secret=None):
    "Reverse of encode_object(), raises ValueError if signature fails"
    s = s.encode('utf8') # base64 works on bytestrings, not on unicodes
    if s.count(':') != 1:
        raise ValueError, 'Should be one and only one colon'
    base64d, sig1 = s.split(':')
    sig2 = hashlib.sha1(base64d + (secret or settings.SECRET_KEY)).hexdigest()
    if sig1 != sig2:
        raise ValueError, 'Signature failed: %s != %s' % (sig1, sig2)
    compressed = base64.urlsafe_b64decode(base64d)
    pickled = zlib.decompress(compressed)
    return pickle.loads(pickled)

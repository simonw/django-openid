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
def encode_object(obj, secret = None):
    """
    Returns URL-safe, sha1 signed base64 compressed pickle. If secret is 
    None, settings.SECRET_KEY is used instead.
    """
    pickled = pickle.dumps(obj)
    compressed = zlib.compress(pickled)
    base64d = base64.urlsafe_b64encode(compressed)
    return sign(base64d, secret)

def decode_object(s, secret = None):
    "Reverse of encode_object(), raises ValueError if signature fails"
    s = s.encode('utf8') # base64 works on bytestrings, not on unicodes
    try:
        base64d = unsign(s, secret)
    except ValueError:
        raise
    compressed = base64.urlsafe_b64decode(base64d)
    pickled = zlib.decompress(compressed)
    return pickle.loads(pickled)


# Utility functions for signing a string using SHA1, then shrinking that SHA1
# hash down to as short as possible using lossless base65 compression.

BASE10 = "0123456789"
# Characters that are NOT encoded by urllib.urlencode:
URLSAFE = '-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz'

import hashlib

class BadSignature(ValueError):
    # Extends ValueError, which makes it more convenient to catch
    pass

def sign(value, key = None):
    if isinstance(value, unicode):
        raise TypeError, \
            'sign() needs bytestring, not unicode: %s' % repr(value)
    if key is None:
        key = settings.SECRET_KEY
    return value + ':' + base65_sha1(value + key)

def unsign(signed_value, key = None):
    if isinstance(signed_value, unicode):
        raise TypeError, 'unsign() needs bytestring, not unicode'
    if key is None:
        key = settings.SECRET_KEY
    if not ':' in signed_value:
        raise BadSignature, 'Missing sig (no : found in value)'
    value, sig = signed_value.rsplit(':', 1)
    if base65_sha1(value + key) == sig:
        return value
    else:
        raise BadSignature, 'Signature failed: %s' % sig

def base65_sha1(s):
    return int_to_base65(int(hashlib.sha1(s).hexdigest(), 16))

def sha1_from_base65(s):
    i = base65_to_int(s)
    in_hex = hex(i)
    # Tricky bug (discovered through unit tests) - we might get a value like
    # '0xb2e5c3e38924d1ac9ab7c7adea91536d3d1d215L' - which we need to change 
    # back in to a more traditional looking 40 char sha1
    
    # Remove leading '0x'
    in_hex = in_hex.replace('0x', '')
    # ... and the trailing L:
    in_hex = in_hex.replace('L', '')
    # And if it's less than 40 chars, add leading '0's as padding
    in_hex = ((40 - len(in_hex)) * '0') + in_hex
    return in_hex

def int_to_base65(i):
    return baseconvert(str(i).lower().replace('L', ''), BASE10, URLSAFE)

def base65_to_int(s):
    return int(baseconvert(s, URLSAFE, BASE10))

def baseconvert(number_string, from_digits, to_digits):
    "Convert a number between two bases of arbitrary digits"
    # Inspired by http://code.activestate.com/recipes/111286/
    # Convert number_string (in from_digits encoding) to an integer
    i = 0L
    for digit in str(number_string):
       i = i * len(from_digits) + from_digits.index(digit)
    # Convert integer to to_digits encoding
    res = []
    while i > 0:
        res.insert(0, to_digits[i % len(to_digits)])
        i = i / len(to_digits)
    return ''.join(res)


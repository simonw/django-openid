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
    sig = sign(base64d, (secret or settings.SECRET_KEY))
    return base64d + ':' + sig

def decode_object(s, secret=None):
    "Reverse of encode_object(), raises ValueError if signature fails"
    s = s.encode('utf8') # base64 works on bytestrings, not on unicodes
    if s.count(':') != 1:
        raise ValueError, 'Should be one and only one colon'
    base64d, sig = s.split(':')
    if not verify(base64d, (secret or settings.SECRET_KEY), sig):
        raise ValueError, 'Signature failed: %s' % sig
    compressed = base64.urlsafe_b64decode(base64d)
    pickled = zlib.decompress(compressed)
    return pickle.loads(pickled)


# Utility functions for signing a string using SHA1, then shrinking that SHA1
# hash down to as short as possible using lossless base65 compression.

BASE10 = "0123456789"
# Characters that are NOT encoded by urllib.urlencode:
URLSAFE = '-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz'

import hashlib

def sign(s, key):
    return base65_sha1(s + ':'  + key)

def verify(s, key, sig):
    return sign(s, key) == sig

def base65_sha1(s):
    return int_to_base65(int(hashlib.sha1(s).hexdigest(), 16))

def sha1_from_base65(s):
    i = base65_to_int(s)
    return hex(i).replace('0x', '')

def int_to_base65(i):
    return baseconvert(str(i).lower().replace('L', ''), BASE10, URLSAFE)

def base65_to_int(s):
    return baseconvert(s, URLSAFE, BASE10)

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


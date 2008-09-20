"""
Functions for creating and restoring url-safe signed pickles.
"""
import pickle, base64, hashlib, zlib
from django.conf import settings

def dumps(obj, secret = None, compress = False):
    """
    Returns URL-safe, sha1 signed base64 compressed pickle. If secret is 
    None, settings.SECRET_KEY is used instead.
    
    If compress is True (not the default) checks if compressing using zlib can
    save some space. Prepends a '.' to signify compression. This is included 
    in the signature, to protect against zip bombs.
    """
    pickled = pickle.dumps(obj)
    is_compressed = False # Flag for if it's been compressed or not
    if compress:
        compressed = zlib.compress(pickled)
        if len(compressed) < (len(pickled) - 1):
            pickled = compressed
            is_compressed = True
    base64d = base64.urlsafe_b64encode(pickled).strip('=')
    if is_compressed:
        base64d = '.' + base64d
    return sign(base64d, secret)

def loads(s, secret = None):
    "Reverse of dumps(), raises ValueError if signature fails"
    s = s.encode('utf8') # base64 works on bytestrings, not on unicodes
    try:
        base64d = unsign(s, secret)
    except ValueError:
        raise
    decompress = False
    if base64d[0] == '.':
        # It's compressed; uncompress it first
        base64d = base64d[1:]
        decompress = True
    pickled = base64.urlsafe_b64decode(base64d + '=' * (len(base64d) % 4))
    if decompress:
        pickled = zlib.decompress(pickled)
    return pickle.loads(pickled)

class BadSignature(ValueError):
    # Extends ValueError, which makes it more convenient to catch
    pass

def sign(value, key = None):
    if isinstance(value, unicode):
        raise TypeError, \
            'sign() needs bytestring, not unicode: %s' % repr(value)
    if key is None:
        key = settings.SECRET_KEY
    return value + '.' + base64_sha1(value + key)

def unsign(signed_value, key = None):
    if isinstance(signed_value, unicode):
        raise TypeError, 'unsign() needs bytestring, not unicode'
    if key is None:
        key = settings.SECRET_KEY
    if not '.' in signed_value:
        raise BadSignature, 'Missing sig (no . found in value)'
    value, sig = signed_value.rsplit('.', 1)
    if base64_sha1(value + key) == sig:
        return value
    else:
        raise BadSignature, 'Signature failed: %s' % sig

def base64_sha1(s):
    return base64.urlsafe_b64encode(hashlib.sha1(s).digest()).strip('=')

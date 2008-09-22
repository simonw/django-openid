from django_openid import signed
from django.conf import settings

from unittest import TestCase

class TestSignUnsign(TestCase):

    def test_sign_unsign_no_unicode(self):
        "sign/unsign functions should not accept unicode strings"
        self.assertRaises(TypeError, signed.sign, u'\u2019')
        self.assertRaises(TypeError, signed.unsign, u'\u2019')
    
    def test_sign_uses_correct_key(self):
        "If a key is provided, sign should use it; otherwise, use SECRET_KEY"
        s = 'This is a string'
        self.assertEqual(
            signed.sign(s),
            s + '.' + signed.base64_sha1(s + settings.SECRET_KEY)
        )
        self.assertEqual(
            signed.sign(s, 'sekrit'),
            s + '.' + signed.base64_sha1(s + 'sekrit')
        )
    
    def sign_is_reversible(self):
        examples = (
            'q;wjmbk;wkmb',
            '3098247529087',
            '3098247:529:087:',
            'jkw osanteuh ,rcuh nthu aou oauh ,ud du',
            u'\u2019'.encode('utf8'),
        )
        for example in examples:
            self.assert_(example != signed.sign(example))
            self.assertEqual(example, signed.unsign(utils.sign(example)))
    
    def unsign_detects_tampering(self):
        value = 'Another string'
        signed_value = signed.sign(value)
        transforms = (
            lambda s: s.upper(),
            lambda s: s + 'a',
            lambda s: 'a' + s[1:],
            lambda s: s.replace(':', ''),
        )
        self.assertEqual(value, signed.unsign(signed_value))
        for transform in transforms:
            self.assertRaises(
                signed.BadSignature, signed.unsign, transform(signed_value)
            )

class TestEncodeDecodeObject(TestCase):
    
    def test_encode_decode(self):
        objects = (
            ('a', 'tuple'),
            'a string',
            u'a unicode string \u2019',
            {'a': 'dictionary'},
        )
        for o in objects:
            self.assert_(o != signed.dumps(o))
            self.assertEqual(o, signed.loads(signed.dumps(o)))
    
    def test_decode_detects_tampering(self):
        transforms = (
            lambda s: s.upper(),
            lambda s: s + 'a',
            lambda s: 'a' + s[1:],
            lambda s: s.replace('.', ''),
        )
        value = {'foo': 'bar', 'baz': 1}
        encoded = signed.dumps(value)
        self.assertEqual(value, signed.loads(encoded))
        for transform in transforms:
            self.assertRaises(
                signed.BadSignature, signed.loads, transform(encoded)
            )

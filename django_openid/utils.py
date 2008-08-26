from openid.yadis import xri
import datetime

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

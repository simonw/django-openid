from django.http import HttpResponse
from django.template import loader, Context, RequestContext

class SimpleTemplateResponse(HttpResponse):
    
    def __init__(self, template, context, *args, **kwargs):
        # These two properties were originally called 'template' and 'context'
        # but django.test.client.Client was clobbering those leading to really
        # tricky-to-debug problems
        self.template_name = template
        self.template_context = context
        self.baked = False
        super(SimpleTemplateResponse, self).__init__(*args, **kwargs)
    
    def resolve_template(self, template):
        "Accepts a template object, path-to-template or list of paths"
        if isinstance(template, (list, tuple)):
            return loader.select_template(template)
        elif isinstance(template, basestring):
            return loader.get_template(template)
        else:
            return template
    
    def resolve_context(self, context):
        "context can be a dictionary or a context object"
        if isinstance(context, Context):
            return context
        else:
            return Context(context)
    
    def render(self):
        template = self.resolve_template(self.template_name)
        context = self.resolve_context(self.template_context)
        content = template.render(context)
        return content
    
    def bake(self):
        """
        The template is baked the first time you try to access 
        response.content or iterate over it. This is a bit ugly, but is 
        necessary because Django middleware sometimes expects to be able to 
        over-write the content of a response.
        """
        if not self.baked:
            self.force_bake()
    
    def force_bake(self):
        "Call this if you have modified the template or context but are "
        "unsure if the template has already been baked."
        self._set_content(self.render())
        self.baked = True
    
    def __iter__(self):
        self.bake()
        return super(SimpleTemplateResponse, self).__iter__()
    
    def _get_content(self):
        self.bake()
        return super(SimpleTemplateResponse, self)._get_content()
    
    def _set_content(self, value):
        "Overrides rendered content, unless you later call force_bake()"
        return super(SimpleTemplateResponse, self)._set_content(value)
    
    content = property(_get_content, _set_content)

class TemplateResponse(SimpleTemplateResponse):
    
    def __init__(self, request, template, context, *args, **kwargs):
        # self.request gets over-written by django.test.client.Client - and 
        # unlike template_context and template_name the _request should not 
        # be considered part of the public API.
        self._request = request
        super(TemplateResponse, self).__init__(
            template, context, *args, **kwargs
        )
    
    def resolve_context(self, context):
        if isinstance(context, Context):
            return context
        else:
            return RequestContext(self._request, context)

# Even less verbose alias:
render = TemplateResponse

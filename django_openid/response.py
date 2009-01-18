from django.http import HttpResponse
from django.template import loader, Context, RequestContext

class TemplateResponse(HttpResponse):
    
    def __init__(self, template, context, *args, **kwargs):
        self.template = template
        self.context = context
        self.rendered = False
        super(TemplateResponse, self).__init__(*args, **kwargs)
    
    def resolve_template(self, template):
        # Template can be a template object, path-to-template or list of paths
        if isinstance(template, (list, tuple)):
            return loader.select_template(template)
        elif isinstance(template, basestring):
            return loader.get_template(template)
        else:
            return template
    
    def resolve_context(self, context):
        # Context can be a dictionary or a context object
        if isinstance(context, Context):
            return context
        else:
            return Context(context)
    
    def render(self):
        template = self.resolve_template(self.template)
        context = self.resolve_context(self.context)
        return template.render(context)
    
    def bake(self):
        """
        The template is baked the first time you try to do something with the
        response - access response.content, for example. This is a bit ugly, 
        but is necessary because Django middleware frequently expects to be 
        able to over-write the content of a response.
        """
        if not self.rendered:
            self._set_content(self.render())
            self.rendered = True
    
    def __iter__(self):
        self.bake()
        return super(TemplateResponse, self).__iter__()
    
    def _get_content(self):
        self.bake()
        return super(TemplateResponse, self)._get_content()
    
    def _set_content(self, value):
        return super(TemplateResponse, self)._set_content(value)
    
    content = property(_get_content, _set_content)

class RequestTemplateResponse(TemplateResponse):
    
    def __init__(self, request, template, context, *args, **kwargs):
        self.request = request
        super(RequestTemplateResponse, self).__init__(
            template, context, *args, **kwargs
        )
    
    def resolve_context(self, context):
        if isinstance(context, Context):
            return context
        else:
            return RequestContext(self.request, context)

# Less verbose alias:
render = RequestTemplateResponse

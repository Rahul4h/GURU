from django import template

register = template.Library()

@register.filter
def hasattr(obj, attr_name):
    return hasattr(obj, attr_name)

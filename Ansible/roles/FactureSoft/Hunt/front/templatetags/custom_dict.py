from django.template.defaulttags import register
from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
	if dictionary:
		try:
			return dictionary.get(key)
		except:
			return "No Name"
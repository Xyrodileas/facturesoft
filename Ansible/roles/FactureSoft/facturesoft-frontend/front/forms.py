from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class SignUpForm(UserCreationForm):
    username = forms.CharField(max_length=30, required=False, help_text='Optional.')
    password = forms.CharField(max_length=30, required=False, help_text='Optional.')


    class Meta:
        model = User
        fields = ('username', password', )
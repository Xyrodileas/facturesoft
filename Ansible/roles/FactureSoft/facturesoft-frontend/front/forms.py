from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class SignUpForm(UserCreationForm):
    username = forms.CharField(max_length=30, required=True, help_text='Optional.')
    email = forms.CharField(max_length=30, required=True, help_text='Optional.')
    password = forms.CharField(max_length=30, required=True, help_text='Optional.')

    class Meta:
        model = User
        fields = ('username', 'email', 'password' )

class SignInForm(UserCreationForm):
    username = forms.CharField(max_length=30, required=True, help_text='')
    email = forms.CharField(max_length=30, required=True, help_text='Optional.')
    password = forms.CharField(max_length=30, required=True, help_text='')

    class Meta:
        model = User
        fields = ('username', 'email', 'password' )
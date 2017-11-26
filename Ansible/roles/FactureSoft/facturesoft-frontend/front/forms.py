from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


class SignUpForm(UserCreationForm):
    username = forms.CharField(max_length=30, required=True, help_text='Optional.')
    password = forms.CharField(max_length=30, required=True, help_text='Optional.')


    class Meta:
        model = User
        fields = ('username', 'password' )

class SignInForm(UserCreationForm):
    username = forms.CharField(max_length=30, required=True, help_text='')
    password = forms.CharField(max_length=30, required=True, help_text='')


    class Meta:
        model = User
        fields = ('username', 'password' )
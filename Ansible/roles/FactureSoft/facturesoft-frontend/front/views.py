from django.http import HttpResponse
from django.http import JsonResponse
from django.shortcuts import render
from django.template import loader, Context
from django.db import connection
from django import forms
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect
import requests
from requests.auth import HTTPBasicAuth
import json
import datetime

from front.models import Expense, User

authorized_username="approver"
authorized_password="12345"

def set_cookie(response, key, value, days_expire = 7):
  if days_expire is None:
    max_age = 365 * 24 * 60 * 60  #one year
  else:
    max_age = days_expire * 24 * 60 * 60 
  expires = datetime.datetime.strftime(datetime.datetime.utcnow() + datetime.timedelta(seconds=max_age), "%a, %d-%b-%Y %H:%M:%S GMT")
  response.set_cookie(key, value, max_age=max_age, expires=expires)

def getExpense(username):
    urlGet = 'http://localhost:1323/user/' + username + '/expenses'
    r = requests.get(urlGet, auth=HTTPBasicAuth(authorized_username, authorized_password))
    print("HTTP GET - " + urlGet)

    try:
        expenses = json.loads(r.json())
        jsonResult = r.json()
        print(jsonResult)
    except:
        expenses = []
        print("Empty Result")

    expensesList = []
    for expense in expenses:
        expensesList.append()
    return expensesList

def postExpense(expense):
    r = requests.post('http://localhost:1323/user/' + username + '/expenses', auth=HTTPBasicAuth(authorized_username, authorized_password), json=expense.toDict())
    jsonResult = r.json()
    print(jsonResult)
    return True


def index(request):
    username = request.COOKIES.get('username') 

    if not username:
        template = loader.get_template('home.html')

        context = {}
        return HttpResponse(template.render(context, request))
    else:
        template = loader.get_template('list_Expenses.html')
        expensesUser = getExpense(username)
        context = {'expenses': expensesUser}
        return HttpResponse(template.render(context, request))



def signup(request):
    class SignupForm(forms.Form):
        username = forms.CharField(label='Enter your name', max_length=100)
        password = forms.CharField(label='Password', max_length=100, widget=forms.PasswordInput())

    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password')


            user = {"name": username, "password": raw_password, "isAdmin": True}

            r = requests.post('http://localhost:1323/user', auth=HTTPBasicAuth(authorized_username, authorized_password), json=user)
            jsonResult = r.json()
            print(jsonResult)

            
            template = loader.get_template('home.html')

            context = {}
            httpResponse = HttpResponse(template.render(context, request))
            set_cookie(httpResponse, 'username', username)
            return httpResponse
    else:
        form = SignupForm()
    return render(request, 'signup.html', {'form': form})
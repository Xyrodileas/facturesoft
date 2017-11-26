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
import hashlib
import os
from front.models import Expense, User
import time
from datetime import datetime, timedelta
from datetime import date

authorized_username="approver"
authorized_password="12345"

# Helper to create a cookie, for persistences between pages
def set_cookie(response, key, value, days_expire = 7):
  if days_expire is None:
    max_age = 365 * 24 * 60 * 60  #one year
  else:
    max_age = days_expire * 24 * 60 * 60 
  #expires = datetime.strftime(datetime.utcnow() + datetime.timedelta(seconds=max_age), "%a, %d-%b-%Y %H:%M:%S GMT")
  response.set_cookie(key, value, max_age=max_age)

# Get all the expenses for a specific user
def getExpenses(username):
    urlGet = 'http://localhost:1323/user/' + username + '/expenses'
    r = requests.get(urlGet, auth=HTTPBasicAuth(authorized_username, authorized_password))
    print("HTTP GET - " + urlGet)

    try:
        expensesList = []
        print(r.json())
        expenses = json.loads(r.text)
        jsonResult = r.json()
        print(jsonResult)
        for expense in expenses:
            expensesList.append(expense)
        return expensesList
    except:
        expenses = []
        print("Empty Result2")
        return expenses

# Get all the expenses that are currently pending (not approved)
def getExpenseNonApproved():
    urlGet = 'http://localhost:1323/expenses?approved=false'
    r = requests.get(urlGet, auth=HTTPBasicAuth(authorized_username, authorized_password))
    print("HTTP GET - " + urlGet)

    try:
        expensesList = []
        print(r.json())
        expenses = json.loads(r.text)
        jsonResult = r.json()
        print(jsonResult)
        for expense in expenses:
            expensesList.append(expense)
        return expensesList
    except:
        expenses = []
        print("Empty Result2")
        return expenses
    
# Create a new expense
def postExpense(expense):
    r = requests.post('http://localhost:1323/user/' + username + '/expenses', auth=HTTPBasicAuth(authorized_username, authorized_password), json=expense.toDict())
    jsonResult = r.json()
    print(jsonResult)
    return True

# Update a specific expense with new information
def updateExpense(expense, idExpense):
    r = requests.put('http://localhost:1323/expense/' + idExpense, auth=HTTPBasicAuth(authorized_username, authorized_password), json=expense)
    jsonResult = r.json()
    print(jsonResult)
    return jsonResult

# Helper to validate login
def postLogin(username, password):
    hashed = hashlib.sha256()
    hashed.update(password.encode('utf-8'))
    hexencoded = hashed.hexdigest()
    r = requests.post('http://localhost:1323/login', auth=HTTPBasicAuth(username, hexencoded))
    jsonResult = r.json()
    try:
        if jsonResult["name"] == username:
            return True
        else:
            return False
    except:
        return False

# Helper to get an account's information
def GetAccount(username):
    r = requests.post('http://localhost:1323/login', auth=HTTPBasicAuth(username, hexencoded))
    jsonResult = r.json()
    return jsonResult

# Check if a user is admin
def isAdmin(request, username):
    try:
        r = request.COOKIES.get('admin')
        if r:
            return True
    except:
        print("Err Assess Admin")
        return False
    print("Not Admin")
    return False
# main page when you hit /front
def index(request):
    username = request.COOKIES.get('username') 
    
    # If no username, let's GTFO
    if not username:
        template = loader.get_template('home.html')

        context = {}
        return HttpResponse(template.render(context, request))
    else:
        template = loader.get_template('list_Expenses.html')
        expensesUser = getExpenses(username)
        context = {'expenses': expensesUser, 'username': username, 'admin': isAdmin(request, username)}
        return HttpResponse(template.render(context, request))

# Get a specific depense for a specific user
def getExpense(username, idExpense):
    urlGet = 'http://localhost:1323/expense/' + idExpense
    r = requests.get(urlGet, auth=HTTPBasicAuth(authorized_username, authorized_password))
    print("HTTP GET - " + urlGet)

    try:
        print(r.json())
        expenses = json.loads(r.text)
        jsonResult = r.json()
        print(jsonResult)
        expense = expenses
    except:
        expense = []
        print("Empty Result")
    return expense

# Page to visualize an expense
def expense(request, idExpense):
    username = request.COOKIES.get('username') 

    # If no username, let's GTFO
    if not username:
        template = loader.get_template('home.html')

        context = {}
        return HttpResponse(template.render(context, request))

    urlGet = 'http://localhost:1323/user/' + username + '/expense/' + idExpense
    r = requests.get(urlGet, auth=HTTPBasicAuth(authorized_username, authorized_password))
    print("HTTP GET - " + urlGet)

    try:
        print(r.json())
        expenses = json.loads(r.text)
        jsonResult = r.json()
        print(jsonResult)
        expense = expenses
    except:
        expense = []
        print("Empty Result")
        template = loader.get_template('home.html')

        context = {"expense":expense}
        return HttpResponse(template.render(context, request))


    else:
        template = loader.get_template('list_Expenses.html')
        expensesUser = getExpenses(username)
        context = {'expenses': expensesUser, 'username': username, 'admin': isAdmin(request, username)}
        return HttpResponse(template.render(context, request))

# Page to manage account information, pretty empty right now
def myAccount(request):
    username = request.COOKIES.get('username') 

    # If no username, let's GTFO
    if not username:
        template = loader.get_template('home.html')

        context = {}
        return HttpResponse(template.render(context, request))
    else:
        template = loader.get_template('my_account.html')
        expensesUser = getExpenses(username)
        context = {'expenses': expensesUser, 'username': username, 'admin': isAdmin(request, username)}

        return HttpResponse(template.render(context, request))

# Page to sign up
def signup(request):
    class SignupForm(forms.Form):
        username = forms.CharField(label='Enter your name', required=True, max_length=100)
        password = forms.CharField(label='Password', required=True, max_length=100, widget=forms.PasswordInput())

    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password')
            m = hashlib.sha256()
            m.update(raw_password.encode('utf-8'))
            hashedpassword = m.hexdigest()

            user = {"name": username, "password": hashedpassword, 'admin': False}

            r = requests.post('http://localhost:1323/user', auth=HTTPBasicAuth(authorized_username, authorized_password), json=user)
            jsonResult = r.json()
            print(jsonResult)

            
            template = loader.get_template('home.html')

            context = {'username': username, 'isAdmin': True}
            httpResponse = HttpResponse(template.render(context, request))
            set_cookie(httpResponse, 'username', username)
            set_cookie(httpResponse, 'admin', True)
            return httpResponse
    else:
        form = SignupForm()
    return render(request, 'signup.html', {'form': form})

# Page to log-on (sign-in)
def signIn(request):
    class SignInForm(forms.Form):
        username = forms.CharField(label='Enter your name', required=True,max_length=100)
        password = forms.CharField(label='Password', required=True,max_length=100, widget=forms.PasswordInput())

    if request.method == 'POST':
        form = SignInForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password')

            result = postLogin(username, raw_password)

            template = loader.get_template('home.html')

            context = {'username': username, 'admin': isAdmin(request, username)}
            httpResponse = HttpResponse(template.render(context, request))
            set_cookie(httpResponse, 'username', username)
            set_cookie(httpResponse, 'admin', True)
            return httpResponse
    else:
        form = SignInForm()
    return render(request, 'signIn.html', {'form': form})

# Helper for time, deprecated
def timestamp_microsecond(utc_time):
    td = utc_time - datetime(1970, 1, 1)
    assert td.resolution == timedelta(microseconds=1)
    return (td.days * 86400 + td.seconds) * 10**6 + td.microseconds

# Page to add a new expense
def addExpense(request):
    class AddExpenseForm(forms.Form):
        name = forms.CharField(label='Name', required=True, max_length=100)
        amount = forms.CharField(label='Amount', required=True, max_length=100)
        date = forms.DateField(label='Date', required=True)

    username = request.COOKIES.get('username') 

    if request.method == 'POST':
        form = AddExpenseForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data.get('name')
            amount = form.cleaned_data.get('amount')
            date = form.cleaned_data.get('date')
            username = request.COOKIES.get('username')
            #date = str(date.datetime.now())
            #d = date.now().isoformat("T")
            #print(d)
            d = date.today()
            import rfc3339
            returndate = datetime.combine(d, datetime.min.time())
            returndate = (rfc3339.rfc3339(returndate))
            print(returndate)
            expense = {"user": username , "name": name, "ammount": int(amount), "date":returndate, "approved":False}
            #expense = {"user": username , "name": name, "ammount": amount, "approved":False}
            #date = 1511712133
            r = requests.post('http://localhost:1323/user/'+ username + '/expense', auth=HTTPBasicAuth(authorized_username, authorized_password), json=expense)

            jsonResult = r.json()
            print(jsonResult)

            template = loader.get_template('home.html')

            context = {'username': username, 'admin': isAdmin(request, username)}
            httpResponse = HttpResponse(template.render(context, request))
            
            return httpResponse
    else:
        form = AddExpenseForm()

    return render(request, 'add_expense.html', {'form': form})

# Page to approve the currently pending expenses (Not approved)
def approveExpenses(request):
    username = request.COOKIES.get('username') 

    # If no username, let's GTFO
    if not username:
        template = loader.get_template('home.html')

        context = {}
        return HttpResponse(template.render(context, request))
    else:
        template = loader.get_template('approve_expense.html')
        expensesUser = getExpenseNonApproved()
        context = {'expenses':expensesUser, 'username': username, 'admin': isAdmin(request, username)}
        return HttpResponse(template.render(context, request))

# Page to approve an expense
def approve(request, idExpense):
    username = request.COOKIES.get('username') 

    # If no username, let's GTFO
    if not username:
        template = loader.get_template('home.html')
        print("No username")
        context = {}
        return HttpResponse(template.render(context, request))
    else:
        template = loader.get_template('approved.html')

        expense = getExpense(username, idExpense)
        expense['approved'] = True
        updateExpense(expense, idExpense)
        context = {'username': username, 'admin': isAdmin(request, username), 'expenseApproved':expense}
        httpResponse = HttpResponse(template.render(context, request))
        set_cookie(httpResponse, 'username', username)
        set_cookie(httpResponse, 'isAdmin', True)
        return httpResponse





from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.index, name='home'),

    url(r'^signup/$', views.signup, name='signup'),
    url(r'^signin/$', views.signin, name='signin'),
    url(r'^myAccount/$', views.myAccount, name='myAccount'),
    url(r'^addExpense/$', views.addExpense, name='addExpense'),
    url(r'^expense/(?P<idExpense>[a-z0-9]{23})$', views.addExpense, name='addExpense'),
    url(r'^approveExpenses/$', views.approveExpenses, name='approveExpenses'),
    url(r'^approve/(?P<idExpense>\w*)$', views.approve, name='approve')
    
]
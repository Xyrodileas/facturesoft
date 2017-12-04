from __future__ import unicode_literals

from django.db import models
import datetime
import math
import json


class User(models.Model):
    name = models.CharField(max_length=50)
    email = models.CharField(max_length=30)
    password = models.CharField(max_length=50)
    isAdmin = models.IntegerField()  

    @classmethod
    def create(name, email, password, isAdmin):
    	process = cls(name=name, email=email, password=password, isAdmin=isAdmin)
    	return User

class Expense(models.Model):
    user = models.CharField(max_length=50)  
    name = models.CharField(max_length=50) 
    amount = models.FloatField()
    approved = models.BooleanField()
    date = models.DateTimeField()

    @classmethod
    def create(user, name, amount, approved, date):
        User = cls(user=user, name=name, amount=amount, approved=approved, date=date)
        return User

    def toJson(self):
        jsonFile = {"user": self.user, "name": self.name, "amount": self.amount, "approved": self.approved, "date": self.date}
        return json.dumps(jsonFile)

    def toDict(self):
        dictfile = {"user": self.user, "name": self.name, "amount": self.amount, "approved": self.approved, "date": self.date}
        return dictfile


class DjangoMigrations(models.Model):
    app = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    applied = models.DateTimeField()

    class Meta:
        managed = False
        db_table = 'django_migrations'
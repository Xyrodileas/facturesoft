from django.test import TestCase
from front.views import *

class ViewTestCase(TestCase):

    def test_Graph(self):
        print("test")
        tree(request=0)
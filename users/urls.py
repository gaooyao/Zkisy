# -*- coding: UTF-8 -*-
from django.conf.urls import url

from .views import *

urlpatterns = [
    url(r'^register/$', register, name='register'),
    url(r'^login/$', login, name='login'),
    url(r'^logout/$', logout, name='logout'),
    url(r'^set_password/$', set_password, name='set_password'),
    url(r'^forget_password/$', forget_password, name='forget_password'),
]

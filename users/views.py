# -*- coding: UTF-8 -*-
import re

from django.contrib.auth import authenticate
from django.contrib.auth import login as django_login
from django.contrib.auth import logout as django_logout
from django.contrib.auth.models import User
from django.shortcuts import render_to_response
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response


@api_view(['GET', 'POST'])
def register(request):
    if request.method == 'GET':
        return render_to_response('users/register.html')
    elif request.method == 'POST':
        try:
            username = re.match('^[a-zA-Z0-9]{6,15}$', request.data['username']).group()
            assert username
        except:
            return Response(data={'result': 'Failed', 'reason': '请检查用户名格式是否正确', },
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            password = re.match('^[a-zA-Z0-9]{6,15}$', request.data['password']).group()
            assert password
        except:
            return Response({'result': 'Failed', 'reason': '请检查密码格式是否正确', }, status=status.HTTP_400_BAD_REQUEST)
        try:
            email = re.match('^\w+([-+.]\w+){0,31}@\w+([-.]\w+){0,31}\.\w+([-.]\w+){0,31}$',
                             request.data['email']).group()
            assert email
        except:
            return Response({'result': 'Failed', 'reason': '请检查邮箱是否正确', },
                            status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(username=username):
            return Response({'result': 'Failed', 'reason': '用户名已存在', }, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email=email):
            return Response({'result': 'Failed', 'reason': '邮箱已被使用', }, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.create_user(username, email, password)
            user.save()
        except:
            return Response({'result': 'Failed', 'reason': '注册失败', }, status=status.HTTP_400_BAD_REQUEST)
        return Response({'result': 'Ok', }, status=status.HTTP_200_OK)


@api_view(['GET', 'POST'])
def login(request):
    if request.method == 'GET':
        return render_to_response('users/login.html')
    elif request.method == 'POST':
        try:
            username = re.match('^[a-zA-Z0-9]{6,15}$', request.data['username']).group()
            assert username
        except:
            return Response(data={'result': 'Failed', 'reason': '请检查用户名格式是否正确', },
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            password = re.match('^[a-zA-Z0-9]{6,15}$', request.data['password']).group()
            assert password
        except:
            return Response({'result': 'Failed', 'reason': '请检查密码格式是否正确', }, status=status.HTTP_400_BAD_REQUEST)
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                django_login(request, user)
            return render_to_response('index.html')
        else:
            return Response({'result': 'Failed', 'reason': '用户名或密码错误', }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def logout(request):
    if request.method == 'GET':
        django_logout(request)
        return render_to_response('users/login.html')


@api_view(['GET', 'POST'])
def set_password(request):
    if request.method == 'GET':
        return render_to_response('users/set_password.html')
    elif request.method == 'POST':
        try:
            username = re.match('^[a-zA-Z0-9]{6,15}$', request.data['username']).group()
            assert username
        except:
            return Response(data={'result': 'Failed', 'reason': '请检查用户名格式', },
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            old_password = re.match('^[a-zA-Z0-9]{6,15}$', request.data['old_password']).group()
            assert old_password
        except:
            return Response({'result': 'Failed', 'reason': '请检查旧密码格式', }, status=status.HTTP_400_BAD_REQUEST)
        user = authenticate(username=username, password=old_password)
        if user is not None:
            try:
                new_password = re.match('^[a-zA-Z0-9]{6,15}$', request.data['new_password']).group()
                assert new_password
            except:
                return Response({'result': 'Failed', 'reason': '请检查新密码格式', }, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(request.data['new_password'])
            user.save()
            return Response({'result': 'Ok', }, status=status.HTTP_200_OK)
        return Response({'result': 'Failed', 'reason': '用户不存在或旧密码错误', }, status=status.HTTP_400_BAD_REQUEST)


def forget_password(request):
    if request.method == 'GET':
        return render_to_response('users/register.html')

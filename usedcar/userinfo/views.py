from django.shortcuts import render, redirect
from django.contrib import auth
from django.http import HttpResponse
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.hashers import make_password, check_password
from django.db import DataError, DatabaseError
from django.http import request, response
from django.contrib import messages
from .models import *
from sale.models import *
import logging
import random
import json
# Create your views here.csrf_protect

auth_check = 'MarcelArhut'


def signin(request):
    return render(request, 'login.html')


def register(request):
    if request.user.is_authenticated():
        return redirect('/')
    else:
        return render(request, 'register.html')


def login_(request):
    if request.method == "POST":
        username = request.POST.get('username', '')
        password = request.POST.get('userpwd', '')
        # user = UserInfo.objects.filter().first()
        user = auth.authenticate(username=username, password=password)
        # print('user:',user.username)
        if user is not None and user.is_active:
        # if user.username == username and user.password == password:
            auth.login(request, user)
            return render(request,'index.html',{'request.user.username':user.username})
        else:
            return render(request, 'login.html', {'message':"用户名或密码错误"})
    # return HttpResponse(" ")


new_user = UserInfo()


def register_(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        # print('user:',new_user.username)
        password = request.POST.get('userpwd')
        password1 = request.POST.get('reuserpwd')
        # print('word:', new_user.password)
        if username == '':
            return render(request,'register.html',{'message':'请输入用户名'})
        if password == '':
            return render(request,'register.html',{'message':'请输入密码'})
        if password1 == '':
            return render(request,'register.html',{'message':'请输入确认密码'})
        try:
            olduser = UserInfo.objects.filter(username=username)
            if len(olduser) > 0:
                return render(request, 'register.html', {'message': '用户名已经存在'})
            else:
                new_user.username = username
        except ObjectDoesNotExist as e:
            logging.warning(e)
        if password != password1:
            return render(request, 'register.html', {'message': '两次输入的密码不一致'})
        new_user.password = make_password(password, auth_check, 'pbkdf2_sha1')
        if 'tobuy' in request.POST:
            return render(request, 'buyregister.html')
        if 'tosale' in request.POST:
            return render(request, 'info-message.html')
    # return HttpResponse(" ")


def buyinfo(request):
    if request.method == 'POST':
        username = request.POST.get('realname')
        new_user.realname = username
        new_user.uidentity = request.POST.get("identity")
        new_user.address = request.POST.get("address")
        new_user.cellphone = request.POST.get("phone")
        new_user.sex = request.POST.getlist("gender")[0]
        try:
            new_user.save()
        except ObjectDoesNotExist as e:
            logging.warning(e)
        # print(new_user.realname)
        request.user = UserInfo.objects.filter(realname=username).first()
        # print(request.user.username)
        user = UserInfo.objects.filter().first()
        return render(request,'index.html',context={'request.user.username':request.user.username})


def logout_(request):
    auth.logout(request)
    return redirect('/')


def infomes(request):
    return render(request, 'info-message.html')


def infomes_(request):
    # if request.is_ajax():
    if request.method == 'POST':
        # print(request.POST)
        username = request.POST.get('realname')
        if username == '':
            return render(request,'info-message.html',context={'message':'卖车信息错误:请输入您的真实姓名'})
        new_user.realname = username
        uidentity = request.POST.get("identity")
        if uidentity == '':
            return render(request,'info-message.html',context={'message':'卖车信息错误:请输入正确的身份证号'})
        new_user.uidentity = uidentity
        address = request.POST.get("address")
        if address == '':
            return render(request, 'info-message.html', context={'message': '卖车信息错误:请输入正确的地址'})
        new_user.address = address

        cellphone = request.POST.get('phone')
        if cellphone == '':
            return render(request, 'info-message.html', context={'message': '卖车信息错误:请输入正确的电话'})
        new_user.cellphone = cellphone
        new_user.sex = request.POST.getlist("gender")[0]
        # print(username, uidentity, address, cellphone)
        try:
            new_user.save()
        except:
            return render(request, 'info-message.html', context={'message': '卖车信息错误:已经被注册'})

        brand = Brand()
        brand.btitle = request.POST.getlist("brands")[0]
        try:
            oldbrand = Brand.objects.filter(btitle=brand.btitle)
            if len(oldbrand) > 0:
                brand = oldbrand[0]
            else:
                brand.save()
        except DatabaseError as e:
            logging.warning(e)

        car = Carinfo()
        ctitle = request.POST.get("model")
        if ctitle == '':
            return render(request,'info-message.html',context={'mssage1':'车辆信息错误:请输入正确的车辆型号'})
        car.ctitle = ctitle
        regist_date = request.POST.get("regist_date")
        if regist_date == '':
            return render(request,'info-message.html',context={'mssage1':'车辆信息错误:请输入正确的车辆上牌日期'})
        car.regist_date = regist_date
        engineNo = request.POST.get("engineNo")
        car.engineNo = engineNo
        mileage = request.POST.get("mileage")
        car.mileage = mileage
        car.maintenance_record = request.POST.getlist("isService")[0]

        price = request.POST.get('price')
        if price == '':
            return render(request, 'info-message.html', context={'mssage1': '卖车信息错误:请输入您的期望卖出价格'})
        car.price = price
        # print('price:',price)
        pri = str(price).split('.')[0]
        # print('pri:', pri)
        car.extractprice = int(pri) * 0.02 + int(pri)
        newprice = request.POST.get("newprice")
        if newprice == '':
            return render(request, 'info-message.html', context={'mssage1': '卖车信息错误:已经被使用'})
        car.newprice = newprice

        car.picture = request.FILES.get('pic')
        car.formalities = request.POST.getlist("formalities")[0]
        car.debt = request.POST.getlist("isDebt")[0]
        car.promise = request.POST.get("promise")
        car.serbran = brand
        car.user = new_user
        try:
            car.save()
        except ObjectDoesNotExist as e:
            logging.warning(e)
        request.user = UserInfo.objects.filter(realname=username).first()
        return render(request,'index.html',context={'request.user.username':request.user.username})
    # return HttpResponse(" ")


def service(request):
    return render(request, 'service.html')





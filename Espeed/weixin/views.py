# -*- coding: utf-8 -*-
from django.shortcuts import render
from django.http import HttpResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
import hashlib

from weixin.config import *
from weixin.functions import *
from weixin.models import *

def register(request):
    return render(request,'register.html')


def index(request):
    """
    :param request: 
    :return: 
    # 初始化微信接入
    # 微信接入参考 http://mp.weixin.qq.com/wiki/17/2d4265491f12608cd170a95559800f2d.html
    """""
    if request.method == "GET":
        signature = request.GET.get("signature")
        timestamp = request.GET.get("timestamp")
        nonce = request.GET.get("nonce")
        echostr = request.GET.get("echostr")
        # 放到数组中按字典序排序
        token = WEIXIN_TOKEN
        tmp_list = sorted([token, timestamp, nonce])
        # 把三个字符串拼接在一起进行sha1加密
        tmp_str = "%s%s%s" % tuple(tmp_list)
        tmp_str = hashlib.sha1(tmp_str).hexdigest()
        # 判断与传递进来的 signature 是否一致
        if tmp_str == signature:
            return HttpResponse(echostr)
        else:
            return HttpResponse('')


def create_menu(request):
    """
    # 在微信公共号中创建菜单
    :param request:
    :return:
    """

    menu_data = {}
    button1 = {}
    button1['name'] = '速工找人'
    button1['type'] = 'view'
    button1['url'] = HOME_URL

    menu_data['button'] = [button1]

    post_url = 'https://api.weixin.qq.com/cgi-bin/menu/create?access_token=' + \
        get_access_token()
    post_data = parse_Dict2Json(menu_data)
    resp, content = my_post(post_url, post_data)
    response = parse_Json2Dict(content)

    if response['errcode'] == 0:
        return HttpResponse('create menu OK.')
    else:
        return HttpResponse(
            WEIXIN_ACCESS_TOKEN +
            ' create menu err:' +
            response['errmsg'])

def register(request):
    return render(request, 'login.html')


def chose_role(request):
    return render(request, 'role.html')

def input_name(request):
    return render(request, 'baseProfile.html')


def chose_job_cate(request):
    return render(request, 'jobs.html')

def wokers_or_jobs_list(request):
    return render(request, 'workerList.html')

def usercenter(request):
    render(request, 'userCenter.html')

def profile(request):
    render(request, 'profile.html')

def history(request):
    render(request, 'history.html')

def transaction(request):
    render(request, 'transaction')


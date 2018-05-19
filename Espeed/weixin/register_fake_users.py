# -*- coding: utf-8 -*-
from django.shortcuts import render
from django.http import HttpResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
import hashlib
from datetime import datetime as dt
from django.http import HttpResponseRedirect

from weixin.config import *
from weixin.functions import *
from weixin.models import *

import random
from math import *
import hashlib

name1=['张','金','李','王','赵']
name2=['玉','明','龙','芳','军','玲']
name3=['','立','玲','','国','']
nickname_str = 'zxcvbnmasdfghjklqwertyuiop'
num = '0123456789'


def gen_user(openid,phonenum,username,nickname,sex,jobs,Location_lati,Location_longi):
    user = User.objects.create_user(
        username=openid,
        password='snsapi_userinfo'
    )

    user.is_active = False
    user.save()
    profile = UserProfileBase(
        fromUser=user,
        phonenum=phonenum,
        openId=openid,
        createTime=dt.now(),
        last_login=dt.now(),
    )
    profile.userName = username
    profile.nickName = nickname
    profile.Sex = sex
    profile.city = '广东'
    profile.province = '广州'
    profile.country = '中国'
    profile.avatarAddr = 'http://thirdwx.qlogo.cn/mmopen/luLgB8lHE8VTeMkWypTMyoeCPaiclGtCx3lGrURWKmRkMHFcBEWAyhfGY2Ut0Qlm1KUiciaiarenVibiakEQz5vmvy1yP56P4lEzto/132'
    profile.Jobs = jobs
    profile.Location_lati = Location_lati
    profile.Location_longi = Location_longi
    profile.online = 'True'
    profile.publishTime = dt.now()


    profile.save()


def Distance2(lat1,lng1,lat2,lng2):# 第二种计算方法
    lat1 = float(lat1)
    lat2 = float(lat2)
    lng1 = float(lng1)
    lng2 = float(lng2)
    radlat1=radians(lat1)
    radlat2=radians(lat2)
    a=radlat1-radlat2
    b=radians(lng1)-radians(lng2)
    s=2*asin(sqrt(pow(sin(a/2),2)+cos(radlat1)*cos(radlat2)*pow(sin(b/2),2)))
    earth_radius=6378.137
    s=s*earth_radius
    if s<0:
        return -s
    else:
        return s


if __name__ == '__main__':
    for i in range(200):
        openid = hashlib.md5(''.join([random.choice("0123456789") for i in range(8)])).hexdigest()
        username = random.choice(name1) + random.choice(name2) + random.choice(name3)
        nickname = random.choice(nickname_str) + random.choice(nickname_str) +random.choice(nickname_str) + random.choice(nickname_str)
        phonenum = random.choice(['139','188','185','136','158','151'])+"".join(random.choice("0123456789") for i in range(8))
        sex = random.choice(['1','2'])
        jobs = random.sample(range(1, 10), 2)
        Location_lati = '28.1{i}027215073601'.format(i=i)
        Location_longi = '112.9{i}513532428318'.format(i=i)
        gen_user(openid, phonenum, username, nickname, sex, jobs, Location_lati, Location_longi)
# -*- coding: utf-8 -*-
from django.shortcuts import render
from django.http import HttpResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
import hashlib

from django.http import HttpResponseRedirect

from weixin.config import *
from weixin.functions import *
from weixin.models import *

import random
from math import *
import hashlib
from datetime import datetime as dt

name1=['张','金','李','王','赵']
name2=['玉','明','龙','芳','军','玲']
name3=['','立','玲','','国','']
nickname_str = 'zxcvbnmasdfghjklqwertyuiop'
num = '0123456789'

jobs_cates = [
    {
        'title': "土建木工",
        'value': 1
    }, {
        'title': "装修木工",
        'value': 2
    }, {
        'title': "铺砖工",
        'value': 3
    }, {
        'title': "铁工",
        'value': 4
    }, {
        'title': "空调工",
        'value': 5
    }, {
        'title': "贴墙纸工",
        'value': 6
    }, {
        'title': "刮腻子工",
        'value': 7
    }, {
        'title': "仿古油漆工",
        'value': 8
    }, {
        'title': "油性油漆工",
        'value': 9
    }, {
        'title': "彩绘工",
        'value': 10
    }, {
        'title': "高空作业工",
        'value': 11
    }, {
        'title': "铝焊工",
        'value': 12
    }, {
        'title': "不锈钢焊工",
        'value': 13
    }, {
        'title': "特殊焊工",
        'value': 14
    }, {
        'title': "绿化工",
        'value': 15
    }, {
        'title': "汽修工",
        'value': 16
    }, {
        'title': "铲车/钩机",
        'value': 17
    }, {
        'title': "压路机/泥头车",
        'value': 18
    }, {
        'title': "吊车货车司机",
        'value': 19
    }, {
        'title': "高压电工",
        'value': 20
    }, {
        'title': "低压电工",
        'value': 21
    }, {
        'title': "弱电工",
        'value': 22
    }, {
        'title': "临时杂工",
        'value': 23
    }, {
        'title': "网络布线维护",
        'value': 24
    }, {
        'title': "雕刻师傅",
        'value': 25
    }, {
        'title': "高空作业工",
        'value': 26
    }, {
        'title': "水泥塑石工",
        'value': 27
    }
]
jobs_cates_samp = [i.get('title') for i in jobs_cates]

def gen_user(openid,phonenum,username,nickname,sex,jobs,role,Location_lati,Location_longi,Score):
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
        userName = username,
        nickName = nickname,
        Sex = sex,
        city = '广东',
        province = '广州',
        country = '中国',
        avatarAddr = 'http://thirdwx.qlogo.cn/mmopen/luLgB8lHE8VTeMkWypTMyoeCPaiclGtCx3lGrURWKmRkMHFcBEWAyhfGY2Ut0Qlm1KUiciaiarenVibiakEQz5vmvy1yP56P4lEzto/132',
        Jobs = jobs,
        Role = role,
        Location_lati = Location_lati,
        Location_longi = Location_longi,
        Score = Score,
        online = 'True',
        publishTime = time.time()
         )


    profile.save()


def Distance(lat1,lng1,lat2,lng2):# 第二种计算方法
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


def create_jobcates():

    jobs_cates = [
            {
                'title': "土建木工",
                'value': 1
            }, {
            'title': "装修木工",
            'value': 2
            }, {
            'title': "铺砖工",
            'value': 3
            }, {
            'title': "铁工",
            'value': 4
            }, {
            'title': "空调工",
            'value': 5
            }, {
            'title': "贴墙纸工",
            'value': 6
            }, {
            'title': "刮腻子工",
            'value': 7
            }, {
            'title': "仿古油漆工",
            'value': 8
            }, {
            'title': "油性油漆工",
            'value': 9
            }, {
            'title': "彩绘工",
            'value': 10
            }, {
            'title': "高空作业工",
            'value': 11
            }, {
            'title': "铝焊工",
            'value': 12
            }, {
            'title': "不锈钢焊工",
            'value': 13
            }, {
            'title': "特殊焊工",
            'value': 14
            }, {
            'title': "绿化工",
            'value': 15
            }, {
            'title': "汽修工",
            'value': 16
            }, {
            'title': "铲车/钩机",
            'value': 17
            }, {
            'title': "压路机/泥头车",
            'value': 18
            }, {
            'title': "吊车货车司机",
            'value': 19
            }, {
            'title': "高压电工",
            'value': 20
            }, {
            'title': "低压电工",
            'value': 21
            }, {
            'title': "弱电工",
            'value': 22
            }, {
            'title': "临时杂工",
            'value': 23
            }, {
            'title': "网络布线维护",
            'value': 24
            }, {
            'title': "雕刻师傅",
            'value': 25
            }, {
            'title': "高空作业工",
            'value': 26
            }, {
            'title': "水泥塑石工",
            'value': 27
            },]
    jobs_cates2 = [
        {
            'title': "消防管道专业",
            'value': 28
        },{
            'title': "空调安装",
            'value': 29
            },{
            'title': "造价/预算",
            'value': 30
            },{
            'title': "测绘/测量",
            'value': 31
            },{
            'title': "园林景观设计",
            'value': 32
            },{
            'title': "美工平面设计",
            'value': 33
            },{
            'title': "手绘动漫",
            'value': 34
            },{
            'title': "CAD制图",
            'value': 35
            },{
            'title': "建筑工程师",
            'value': 36
            },{
            'title': "3D设计/制作",
            'value': 37
            },{
            'title': "室内装潢设计",
            'value': 38
            },{
            'title': "供水排水专业",
            'value': 39
            },{
            'title': "文员/助理",
            'value': 40
            },{
            'title': "资料员",
            'value': 41
            },{
            'title': "财务/会计",
            'value': 42
            },{
            'title': "法律顾问",
            'value': 43
            },{
            'title': "机电设备维护",
            'value': 44
            },{
            'title': "沙石水泥",
            'value': 45
            },{
            'title': "其他特殊工种",
            'value': 46
            },
        {
            'title': "铝合金门窗制作",
            'value': 47
        },
        ]
    jobs_cates3 = [
        {
            'title': "室内装饰电工",
            'value': 48
        },        {
            'title': "室内精装铺砖工",
            'value': 49
        },        {
            'title': "市政铺砖工",
            'value': 50
        },
    ]
    for i in jobs_cates3:
        job_cate = Jobcates(id=i.get('value'), jobcate=i.get('title'))
        job_cate.save()

if __name__ == '__main__':
    for i in range(1):
        openid = hashlib.md5(''.join([random.choice("0123456789") for i in range(8)])).hexdigest()
        username = random.choice(name1) + random.choice(name2) + random.choice(name3)
        nickname = random.choice(nickname_str) + random.choice(nickname_str) +random.choice(nickname_str) + random.choice(nickname_str)
        phonenum = random.choice(['139','188','185','136','158','151'])+"".join(random.choice("0123456789") for i in range(8))
        sex = random.choice(['1','2'])
        jobs = set(random.sample(jobs_cates_samp, 2))
        role = random.choice([1,2])
        Location_lati = float(u'28.153687729085096')
        Location_longi = float(u'112.9855580663209')
        Score = random.choice([1,2,3,4,5])
        gen_user(openid, phonenum, username, nickname, sex, jobs,role, Location_lati, Location_longi,Score)
    #print Distance('22.925574625328796','113.27683018769442','28.151706861629958','112.9853043363359')
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.contrib.auth.models import User

from django.db import models

# Create your models here.

class UserProfileBase(models.Model):
    #  "改造用户身份认证所需表结构"
    fromUser = models.OneToOneField(User)
    nickName = models.CharField(max_length=30)		# 微信昵称
    openId = models.CharField(max_length=50)        # Openid
    Sex = models.IntegerField(default=True)			# 微信标识的性别
    userName = models.CharField(max_length=30)			# 用户真实名称，注册时输入的
    country = models.CharField(max_length=30)			# 国家
    province = models.CharField(max_length=30)		# 省份
    city = models.CharField(max_length=30)			# 城市
    phonenum = models.CharField(max_length=20)				# 电话
    avatarAddr = models.URLField()						# 头像
    Role = models.IntegerField(default=True)	    # 身份
    Location_lati = models.CharField(max_length=100)     # 定位
    Location_longi = models.CharField(max_length=100)  # 定位
    Score = models.IntegerField(default=True)       # 评分
    Jobs = models.TextField(null=True)              # 工种类型
    online = models.BooleanField(default=False)     # 是否在线
    createTime = models.DateField()						# 注册时间
    last_login = models.DateField(default=None)			# 最后访问时间
    publishTime = models.DateField(default=None,null=True)

class UserVisible(models.Model):
    user_payed = models.CharField(max_length=50)  # Openid
    user_visible = models.CharField(max_length=50)  # Openid


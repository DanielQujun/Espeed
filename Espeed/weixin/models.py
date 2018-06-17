# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.contrib.auth.models import User

from django.db import models
from django_mysql.models import SetTextField
import datetime

# Create your models here.

class UserProfileBase(models.Model):
    
    class Meta:
        verbose_name = '用户信息数据表'
        verbose_name_plural = '用户信息数据表'
        
    #  "改造用户身份认证所需表结构"
    fromUser = models.OneToOneField(User)
    nickName = models.CharField(max_length=30)		# 微信昵称
    openId = models.CharField(max_length=50)        # Openid
    Sex = models.IntegerField(default=True)			# 微信标识的性别
    userName = models.CharField(u"用户名", max_length=30)			# 用户真实名称，注册时输入的

    country = models.CharField(max_length=30)			# 国家
    province = models.CharField(max_length=30)		# 省份
    city = models.CharField(max_length=30)			# 城市
    phonenum = models.CharField(u"电话号码", max_length=20)				# 电话
    avatarAddr = models.URLField()						# 头像
    Role = models.IntegerField(default=True)	    # 身份
    Location_lati = models.FloatField(null=True)     # 定位
    Location_longi = models.FloatField(null=True)  # 定位
    Score = models.IntegerField(default=5)       # 评分
    ScoreCount = models.IntegerField(default=True)	# 评价人数
    Jobs = SetTextField(
        base_field=models.CharField(max_length=32),
    )           # 工种类型
    online = models.BooleanField(u"是否在线",default=False)     # 是否在线
    createTime = models.DateTimeField(u"创建时间", auto_now_add=True)				# 注册时间
    last_login = models.DateField(default=None)			# 最后访问时间
    publishTime = models.CharField(max_length=20, null=True)
    last_login2 = models.CharField(max_length=20, null=True)


    def login_time_str(self):
        if self.last_login2:
            xx = datetime.datetime.fromtimestamp(float(self.last_login2))
            strtime = xx.strftime('%Y-%m-%d %H:%M:%S')
        else:
            xx = datetime.datetime.fromtimestamp(1529127035.18)
            strtime = xx.strftime('%Y-%m-%d %H:%M:%S')

        return strtime

    def pub_time_str(self):
        if self.publishTime:
            xx = datetime.datetime.fromtimestamp(float(self.publishTime))
            strtime = xx.strftime('%Y-%m-%d %H:%M:%S')
        else:
            strtime = "----"

        return strtime

    def role_for_admin(self):
        if self.Role == 1:
            return u"工人"
        else:
            return u"老板"
    def Jobs_for_admin(self):
        job_string = ""
        if self.Jobs:

            for job in self.Jobs:

                job_string += job
                job_string += "， "
        return job_string


    login_time_str.short_description = "上次登录时间"
    pub_time_str.short_description = "发布时间"
    role_for_admin.short_description = "用户身份"
    Jobs_for_admin.short_description = "用户工种"


    Jobs_for_a = property(Jobs_for_admin)
    role_for_a = property(role_for_admin)
    login_time_p = property(login_time_str)
    pub_time_p = property(pub_time_str)

class UserVisible(models.Model):
    transation_no = models.CharField(default=None, max_length=50)
    paysign = models.CharField(default=None, max_length=50)
    user_payed = models.CharField(max_length=50)  # Openid
    user_visible = models.CharField(max_length=50)  # Openid
    pay_status = models.CharField(default='prepay', max_length=50)
    request_time = models.CharField(max_length=20, null=True,blank=True,default=None)
    payed_time = models.CharField(max_length=20, null=True,blank=True, default=None)

class Jobcates(models.Model):
    class Meta:
        verbose_name = '工种列表'
        verbose_name_plural = '工种列表'
    jobcate = models.CharField(max_length=32)

class transations(models.Model):
    transations_user = models.CharField(max_length=50)

class verify_code_request(models.Model):
    request_ip = models.CharField(max_length=50)
    request_phonenum = models.CharField(max_length=50)
    request_time = models.CharField(max_length=50)

class send_template(models.Model):
    useropenid = models.DateField(default=None)
#encoding:utf-8
from django.db import models
from django.contrib.auth.models import User
from django.template.defaultfilters import slugify

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
    tel = models.CharField(max_length=20)				# 电话
    avatarAddr = models.URLField()						# 头像
    Role = models.IntegerField(default=True)	    # 身份
    Location = models.CharField(max_length=100)     # 定位
    Score = models.IntegerField(default=True)       # 评分
    createTime = models.DateField()						# 注册时间
    lastTime = models.DateField()						# 最后访问时间

    class Meta:
        abstract = True

    # 可以再增加其他字段，比如从微信获取到的用户籍贯等信息

class BossInfo(UserProfileBase):

    def __unicode__(self):
        return self.fromUser.nickName


class WorkerInfo(UserProfileBase):

    def __unicode__(self):
        return self.fromUser.nickName


class JobType(models.Model):
    jobid = models.IntegerField(default=True)
    jobtypes = models.CharField(max_length=20)


class Score(models.Model):
    pass


class Location(models.Model):
    pass


class Transaction(models.Model):
    pass

class complaints(models.Model):
    pass

# -*- coding: utf-8 -*-
from django.contrib import admin
from weixin.models import UserProfileBase

@admin.register(UserProfileBase)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('userName', 'phonenum', 'Role', 'Jobs','online','createTime','last_login','publishTime')

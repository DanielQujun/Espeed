# -*- coding: utf-8 -*-
from django.contrib import admin
from weixin.models import UserProfileBase, Jobcates

admin.site.site_header = 'E我速工后台'
admin.site.site_title = 'E我速工后台'


@admin.register(UserProfileBase)
class UserProfileAdmin(admin.ModelAdmin):

    list_display = ('userName', 'phonenum', 'role_for_a', 'Jobs_for_a', 'online','createTime', 'pub_time_p','login_time_p')


@admin.register(Jobcates)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('jobcate',)

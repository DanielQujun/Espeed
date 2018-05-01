"""Espeed URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
import views
import weixin.views as weixin_views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^wechat/', weixin_views.index, name='index'),
    url(r'^register/', weixin_views.register, name='register'),
    url(r'^role/', weixin_views.chose_role, name='chose_role'),
    url(r'^baseProfile/', weixin_views.input_name, name='input_name'),
    url(r'^jobs/', weixin_views.chose_job_cate, name='chose_job_cate'),
    url(r'^workerList/', weixin_views.wokers_or_jobs_list, name='wokers_or_jobs_list'),
    url(r'^userCenter/', weixin_views.usercenter, name='usercenter'),
    url(r'^profile/', weixin_views.profile, name='profile'),
    url(r'^history/', weixin_views.history, name='history'),
    url(r'^transaction/', weixin_views.transaction, name='transaction'),
    url(r'^create_menu/', weixin_views.create_menu, name = 'create_menu'),
]

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
import weixin.views as weixin_views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^wechat/', weixin_views.chushihua, name='index'),
    url(r'^register/', weixin_views.register, name='register'),
    url(r'^guide/', weixin_views.guide, name='guide'),
    url(r'^role/', weixin_views.chose_role, name='chose_role'),
    url(r'^baseProfile/', weixin_views.input_name, name='input_name'),
    url(r'^jobs/', weixin_views.chose_job_cate, name='chose_job_cate'),
    url(r'^workerList/', weixin_views.workers_or_jobs_list, name='wokers_or_jobs_list'),
    url(r'^userCenter/', weixin_views.usercenter, name='usercenter'),
    url(r'^profile/', weixin_views.profile, name='profile'),
    url(r'^history/', weixin_views.history, name='history'),
    url(r'^transaction/', weixin_views.transaction, name='transaction'),
    url(r'^create_menu/', weixin_views.create_menu, name='create_menu'),
    url(r'^worklist_ajax/',weixin_views.worklist_ajax, name='worklist_ajax'),
    url(r'^wxpay/notify/',weixin_views.wxpay_notify, name='wxpay_notify'),
    url(r'^zhihu_pre/', weixin_views.zhihu_pre, name='zhihu_pre'),
    url(r'^dail/', weixin_views.dail, name='dail'),
    url(r'^verify_code/',weixin_views.verify_code, name='verify_code'),
    url(r'^history_ajax/',weixin_views.history_ajax, name='history_ajax'),
    url(r'^complain/',weixin_views.complain, name='complain'),
    url(r'^transaction_ajax/', weixin_views.transaction_ajax, name='transaction_ajax'),
    url(r'^rate/', weixin_views.rate, name='rate'),
    url(r'^change_username/', weixin_views.change_username, name='change_username'),
    url(r'^nearby_jobs/', weixin_views.nearby_jobs, name='nearby_jobs'),
    url(r'^nearby/', weixin_views.nearby_workers, name='nearby_workers'),
    url(r'^nearby_ajax/', weixin_views.nearby_ajax, name='nearby_ajax'),
    url(r'^shareCode/', weixin_views.shareCode, name='shareCode'),
    url(r'^moment_shared_notify/', weixin_views.moment_shared_notify, name='moment_shared_notify'),
    url(r'^userrepresentation/', weixin_views.userrepresentation, name='userrepresentation'),
    url(r'^uploadimg/', weixin_views.uploadFile, name='uploadimg')

]

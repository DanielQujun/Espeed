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


def index(request):
    callbackurl = "/register"
    return HttpResponseRedirect(callbackurl)

def chushihua(request):
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
    elif request.method == "POST":
        raw_xml = request.body.decode(u'UTF-8')
        dict_str = parse_Xml2Dict(raw_xml)
        try:
            MsgType = dict_str['MsgType']
        except BaseException:
            MsgType = ''
        try:
            Event = dict_str['Event']
        except BaseException:
            Event = ''
        if MsgType == 'text':  # 当接收到用户发来的文本信息时
            res_dict = {}
            res_dict['ToUserName'] = dict_str['FromUserName']
            res_dict['FromUserName'] = dict_str['ToUserName']
            res_dict['CreateTime'] = int(time.time())
            res_dict['MsgType'] = 'text'
            res_dict['Content'] = dict_str['Content']
            echostr = parse_Dict2Xml('xml', res_dict)
            return HttpResponse(echostr)
        elif MsgType == 'image':
            send_text(dict_str['FromUserName'], "收到你发送的图片")
            return HttpResponse('')
        elif MsgType == 'voice':
            dict_user_info = get_user_info(dict_str['FromUserName'])
            print '------------------------------'
            print '发送语音的用户信息如下'
            print dict_user_info
            print dict_user_info['nickname'].encode('utf-8')
            print '------------------------------'
            return HttpResponse('')
        elif Event == 'subscribe':  # 关注公众号事件
            if dict_str['EventKey'] and dict_str['Ticket']:  # 通过扫描二维码进行关注
                qrcode_num = dict_str['EventKey'].split('_')[1]
                send_text(
                    dict_str['FromUserName'],
                    "感谢您关注公众号！qrcode is " +
                    str(qrcode_num))
            else:
                send_text(dict_str['FromUserName'], "感谢您关注公众号！")
            return HttpResponse('')
        elif Event == 'SCAN':
            send_text(dict_str['FromUserName'],
                      "qrcode is " + str(dict_str['EventKey']))
            return HttpResponse('')
        elif MsgType == 'location':
            send_text(dict_str['FromUserName'], "你现在在:\n" + dict_str['Label'])
            return HttpResponse('')
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
    if request.method == 'GET':
        data = {}
        data['openid'] = request.GET.get('openid')
        return render(request, 'login.html', data)

    elif request.method == 'POST':
        openid = request.POST.get('openid')
        phonenum = request.POST.get('phonemun')
        veirycode = request.POST.get('verifycode')

        if veirycode and phonenum and openid:

            user = User.objects.create_user(
                username=openid,
                password='snsapi_userinfo'
            )
            # 默认未激活状态，用来判断是否是已经通过认证的学员
            user.is_active = False
            user.save()
            profile = UserProfileBase(
                fromUser=user,
                phonenum=phonenum,
                openId=openid,
                createTime=datetime.datetime.now(),
            )
            profile.save()
            callbackurl = "/role?openid={openid}".format(openid=openid)
            return HttpResponseRedirect(callbackurl)



def chose_role(request):
    if request.method == 'GET':
        data = {}
        data['openid'] = request.GET.get('openid')
        return render(request, 'role.html', data)

    elif request.method == 'POST':
        openid = request.POST.get('openid')
        role = request.POST.get('role')
        if role and openid:

            user = UserProfileBase.objects.filter(openId=openid)
            user.role = role
            user.save()
            callbackurl = "/baseProfile?openid={openid}".format(openid=openid)
            return HttpResponseRedirect(callbackurl)



def input_name(request):
    if request.method == 'GET':
        data = {}
        data['openid'] = request.GET.get('openid')

        # 准备根据openid来获取基本信息
        baseinfourl = BASEINFOURL.format(WEIXIN_ACCESS_TOKEN=WEIXIN_ACCESS_TOKEN, OPENID=data['openid'])
        resp, content = my_get(baseinfourl)
        user_info_dict = parse_Json2Dict(content)
        print user_info_dict

        return render(request, 'baseProfile.html', user_info_dict)
    elif request.method == 'POST':
        POST_DATA = request.POST

        if not None in POST_DATA.values():
            user = UserProfileBase.objects.filter(openId=POST_DATA.get('openid')).first()
            user.userName = POST_DATA.get('username')
            user.nickName = POST_DATA.get('nickname')
            user.Sex = POST_DATA.get('sex')
            user.city = POST_DATA.get('city')
            user.province = POST_DATA.get('province')
            user.country = POST_DATA.get('country')
            user.avatarAddr =POST_DATA.get('headimgurl')

            user.fromUser.is_alive = True
            user.save()
            callbackurl = RedirectURL.format(WEIXIN_APPID=WEIXIN_APPID, CALLBACK="http://bobozhu.cn/jobs")
            return HttpResponseRedirect(callbackurl)
        else:
            return "bad post data"



def chose_job_cate(request):
    if request.method == 'GET':
        data = {}
        data['openid'] = request.GET.get('openid')

        return render(request, 'jobs.html', data)

    elif request.method == 'POST':
        POST_DATA = request.POST
        openid = POST_DATA.get('openid')
        if not None in POST_DATA.values() and openid:
            if POST_DATA.get('online'):
                user = UserProfileBase.objects.filter(openId=openid).first()
                user.jobs = POST_DATA.get('jobs')
                user.Location = POST_DATA.get('location')
                user.online = POST_DATA.get('online')
                user.save()
            else:
                pass

        callbackurl = "/workerList?openid={openid}".format(openid=openid)
        return HttpResponseRedirect(callbackurl)

def wokers_or_jobs_list(request):
    print request.GET
    "获取用户 openid 判定 ID 是否是认证用户来跳转不同的页面"
    # http://www.cnblogs.com/txw1958/p/weixin71-oauth20.html
    code = request.GET.get("code", "")
    state = request.GET.get("state", "")
    openid = request.GET.get("openid", "")

    if not code and not openid:
        return HttpResponse('非法访问...')
    user_dict = {}

    # 构造请求 openid 的 url，使用 get 方式请求该 url，将得到的数据转为字典
    if code:
        url = 'https://api.weixin.qq.com/sns/oauth2/access_token?appid=' + WEIXIN_APPID + \
            '&secret=' + WEIXIN_APPSECRET + '&code=' + code + '&grant_type=authorization_code'
        resp, content = my_get(url)
        user_dict = parse_Json2Dict(content)
        print user_dict
    elif openid:
        user_dict['openid'] = openid
        user_dict['scope'] = "snsapi_userinfo"

    user = authenticate(
        username=user_dict['openid'],
        password=user_dict['scope']
    )
    if user is not None:
        # 用户存在，判断用户是否是认证用户
        if user.is_active:
            # 登录用户，其他任何途径都无法登录用户，后面使用装饰器验证用户是否登录来防止一些页面被用户直接访问

            # 取用户信息
            profile = UserProfileBase.objects.get(fromUser=user)

            phonenum = profile.phonenum
            if phonenum:
                login(request, user)

                # 获取用户的个人信息
                userInfo = {}


                return render(request, 'workerList.html')
            else:
                return HttpResponseRedirect('/register/')

        else:
            # 修改前台用来显示的文字
            showUrl = HOME_URL
            showText = "审核中，请等待..."
    else:
        callbackurl = "/register?openid={openid}".format(openid=user_dict['openid'])
        return HttpResponseRedirect(callbackurl)

@login_required
def usercenter(request):
    return render(request, 'userCenter.html')
@login_required
def profile(request):
    return render(request, 'profile.html')
@login_required
def history(request):
    return render(request, 'history.html')
@login_required
def transaction(request):
    return render(request, 'transaction')


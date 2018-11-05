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

import xml.etree.ElementTree as et

from weixin.config import *
from weixin.functions import *
from weixin.models import *
from django.db.models import Q
from django.core.paginator import Paginator
from wx_pay import WxPay, WxPayError
from aliyunsdkcore.client import AcsClient
import uuid
from aliyunsdkcore.profile import region_provider
from aliyunsdkdysmsapi.request.v20170525 import SendSmsRequest
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


import redis
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT)


def index(request):
    callbackurl = "/register"
    return HttpResponseRedirect(callbackurl)


def chushihua(request):
    print "微信初始化！！"
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
        print "微信 POST!!"
        response = HttpResponse(responseMsg(request.body), content_type="application/xml")
    else:
        response = None

    return response


@csrf_exempt
def create_menu(request):
    """
    # 在微信公共号中创建菜单
    :param request:
    :return:
    """

    menu_data = {}
    button1 = {}
    button1['name'] = '点击进入找人找活'
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
        if request.GET.get('verify_code_wrong'):
            data['verify_code_wrong'] = request.GET.get('verify_code_wrong')
        data['openid'] = request.GET.get('openid')
        return render(request, 'login.html', data)

    elif request.method == 'POST':
        logger.info("qujun:get register post!")
        logger.info(request.POST)
        openid = request.POST.get('openid')
        phonenum = request.POST.get('phoneNum')
        veirycode = request.POST.get('signCode')
        if veirycode == request.session['verify_code'] and time.time() - request.session.get('verify_code_time') < 300:
            if phonenum and openid:

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
                profile.save()
                callbackurl = "/baseProfile/?openid={openid}".format(openid=openid)
                return HttpResponseRedirect(callbackurl)
            else:
                print 'qujun:信息不全！！'
                callbackurl = "/register/?openid={openid}".format(openid=openid)
                return HttpResponseRedirect(callbackurl)
        else:
            callbackurl = "/register/?openid={openid}&verify_code_wrong='verify_code_wrong".format(openid=openid)
            return HttpResponseRedirect(callbackurl)


def chose_role(request):
    if request.method == 'GET':
        data = {}
        data['openid'] = request.GET.get('openid')
        return render(request, 'role.html', data)

    elif request.method == 'POST':
        logger.info("i am in chose role!!")
        print request.POST
        openid = request.POST.get('openid')
        role = request.POST.get('role')
        if role and openid:

            user = UserProfileBase.objects.filter(openId=openid).first()
            user.Role = role
            user.online = 'False'
            user.save()
            callbackurl = "/jobs/?openid={openid}".format(openid=openid)
            return HttpResponseRedirect(callbackurl)


def input_name(request):
    if request.method == 'GET':
        data = {}
        data['openid'] = request.GET.get('openid')

        # 准备根据openid来获取基本信息
        baseinfourl = BASEINFOURL.format(WEIXIN_ACCESS_TOKEN=get_access_token(), OPENID=data['openid'])
        resp, content = my_get(baseinfourl)
        user_info_dict = parse_Json2Dict(content)

        return render(request, 'baseProfile.html', user_info_dict)
    elif request.method == 'POST':
        logger.info("qujun: iam in inpurt name!")
        POST_DATA = request.POST
        print POST_DATA

        if POST_DATA.values():
            user = UserProfileBase.objects.filter(openId=POST_DATA.get('openid')).first()
            user.userName = POST_DATA.get('username')
            user.nickName = POST_DATA.get('nickname')
            user.Sex = POST_DATA.get('sex')
            user.city = POST_DATA.get('city')
            user.province = POST_DATA.get('province')
            user.country = POST_DATA.get('country')
            user.avatarAddr =POST_DATA.get('headimgurl')

            user.fromUser.is_active = True
            user.fromUser.save()
            user.save()
            #callbackurl = RedirectURL.format(WEIXIN_APPID=WEIXIN_APPID, CALLBACK="http://ewosugong.com/jobs")
            callbackurl = "/role/?openid={openid}".format(openid=POST_DATA.get('openid'))
            return HttpResponseRedirect(callbackurl)
        else:
            return "bad post data"


def chose_job_cate(request):
    if request.method == 'GET':
        data = {}
        data['openid'] = request.GET.get('openid')
        data['timestamp'] = int(time.time())
        data['nonceStr'] = 'qujunqujun'
        data['appid'] = WEIXIN_APPID
        data['jsapi_ticket'] = get_jsapi_token()
        data['url'] = request.build_absolute_uri()
        jsapi_string = "jsapi_ticket={JSAPI_TICKET}&noncestr={NONCESTR}&timestamp={TIMESTAMP}&url={URL}".\
            format(JSAPI_TICKET=data['jsapi_ticket'],NONCESTR=data['nonceStr'], TIMESTAMP=data['timestamp'], URL=data['url'])

        data['signature'] = hashlib.sha1(jsapi_string).hexdigest()

        data['jobList'] = []

        jobcates = Jobcates.objects.all()
        for jobcate in jobcates:
            job_dic = {'title': jobcate.jobcate, 'value': jobcate.id}
            data['jobList'].append(job_dic)
        data['jobList'] = json.dumps(data['jobList'])

        return render(request, 'jobs.html', data)

    elif request.method == 'POST':

        POST_DATA = request.POST
        print POST_DATA
        openid = POST_DATA.get('openid')
        if not None in POST_DATA.values() and openid:
            if POST_DATA.get('online') == 'true':
                print "qujun : update database for jobs choose!!!"
                print request.POST
                user = UserProfileBase.objects.filter(openId=openid).first()
                user.Jobs = POST_DATA.get('tag')
                user.Location_lati = float(POST_DATA.get('latitude'))
                user.Location_longi = float(POST_DATA.get('longitude'))
                user.online = 'True'
                user.publishTime = time.time()
                user.save()
                send_online_to_redis(user.userName,user.openId, user.Role,user.Jobs,user.phonenum,user.Location_lati,
                                     user.Location_longi,user.publishTime)
                callbackurl = "/workerList/?openid={openid}".format(openid=openid)
                return HttpResponse("OK")
                # return HttpResponseRedirect(callbackurl)
            else:
                logger.error("update database for %s jobs OFFline!!!"%openid)
                data = {}
                data['openid'] = openid
                user = UserProfileBase.objects.filter(openId=openid).first()
                user.online = 'False'
                user.save()

                return render(request, 'jobs.html', data)

        else:
            callbackurl = "/register/?openid={openid}".format(openid=openid)
            return HttpResponseRedirect(callbackurl)
            #return HttpResponse('invalid post')


def workers_or_jobs_list(request):

    "获取用户 openid 判定 ID 是否是认证用户来跳转不同的页面"
    # http://www.cnblogs.com/txw1958/p/weixin71-oauth20.html
    code = request.GET.get("code", "")
    state = request.GET.get("state", "")
    openid = request.GET.get("openid", "")
    sort_time = request.GET.get('sorttime',False)

    if not code and not openid:
        return HttpResponse('非法访问...')
    user_dict = {}

    # 构造请求 openid 的 url，使用 get 方式请求该 url，将得到的数据转为字典
    if code:
        url = 'https://api.weixin.qq.com/sns/oauth2/access_token?appid=' + WEIXIN_APPID + \
            '&secret=' + WEIXIN_APPSECRET + '&code=' + code + '&grant_type=authorization_code'
        resp, content = my_get(url)
        logger.info("workers_or_jobs_list get content from weixin code: %s", content)
        user_dict = parse_Json2Dict(content)

    elif openid:
        user_dict['openid'] = openid
        user_dict['scope'] = "snsapi_userinfo"

    if user_dict['openid']:

        user = UserProfileBase.objects.filter(openId=user_dict['openid']).first()
        if user is not None:
            # 用户存在，判断用户是否是认证用户
            if user.fromUser.is_active:
                if user.phonenum:
                    user.last_login2 = time.time()
                    user.save()
                    if user.online:
                        logger.error("qujun: User %s is  Online!"%user.openId)
                        data = render_js_config(request)
                        data['openid'] = user.openId
                        data['role'] = user.Role
                        if sort_time:
                            data['byDis'] = 'false'
                            data['byPubTime'] = 'true'
                        else:
                            data['byDis'] = 'true'
                            data['byPubTime'] = 'true'
                        print data
                        return render(request, 'workerList.html', data)
                    else:
                        logger.error("qujun: User  %s is Not Online!"%user.openId)
                        callbackurl = "/jobs/?openid={openid}".format(openid=user.openId)
                        return HttpResponseRedirect(callbackurl)
                else:
                    return HttpResponseRedirect('/register/?openid={openid}'.format(user_dict['openid']))

            elif not user.Role:
                # 修改前台用来显示的文字
                callbackurl = "/role/?openid={openid}".format(openid=user.openId)
                return HttpResponseRedirect(callbackurl)
            elif not user.userName:
                callbackurl = "/baseProfile/?openid={openid}".format(openid=user.openId)
                return HttpResponseRedirect(callbackurl)

        else:
            callbackurl = "/register/?openid={openid}".format(openid=user_dict['openid'])
            return HttpResponseRedirect(callbackurl)
    else:
        print "user_dict 为空！！！！！"
        return HttpResponse('非法访问...')


# @login_required
def usercenter(request):
    if request.method == 'GET':
        openid = request.GET.get('openid')
        if openid:
            user = UserProfileBase.objects.filter(openId=openid).first()
            data = {}
            data['headimgurl'] = user.avatarAddr
            data['openid'] = openid
            data['username'] = user.userName

            return render(request, 'userCenter.html', data)


# @login_required
def profile(request):
    if request.method == 'GET':
        if request.GET.get('openid'):
            user = UserProfileBase.objects.filter(openId=request.GET.get('openid')).first()
            if user:
                data = {}
                data['openid'] = request.GET.get('openid')
                data['headimgurl'] = user.avatarAddr
                data['username'] = user.userName
                data['phone_num'] = user.phonenum
                jobs = [i for i in user.Jobs]
                data['Jobs'] = ' '.join(jobs)
                data['role'] = user.Role
                return render(request, 'profile.html', data)
        else:
            return HttpResponse(u'非法访问')


# @login_required
def history(request):
    if request.method == 'GET':
        openid = request.GET.get('openid')
        if openid:
            data = {}
            data['openid'] = openid
            return render(request, 'history.html', data)


def history_ajax(request):
    if request.method == 'POST':
        print request.POST
        openid = request.POST.get('openid')
        sortByDis =request.POST.get('sortByDis')
        sortByPubTime = request.POST.get('sortByPubTime')
        page = request.POST.get('page')
        # openid = 'oT69X1Chvefxgv3wby_-PaEIM9nY'
        if openid:
            user = UserProfileBase.objects.filter(openId=openid).first()
            tag_set = user.Jobs.copy()
            # 查询该用户支付过的记录
            payed_list = [payed_user.user_visible for payed_user in UserVisible.objects.filter(user_payed=openid,
                                                                                               pay_status='payed')]

            work_objects_db = []
            for payed_openid in payed_list:
                workers = UserProfileBase.objects.filter(openId=payed_openid)
                for worker in workers:
                    worker_dic = {}
                    worker_dic['userid'] = worker.id
                    worker_dic['username'] = worker.userName
                    worker_dic['tag'] = list(worker.Jobs)
                    #worker_dic['star'] = int(worker.Score)
                    worker_dic['star'] = worker.Score
                    worker_dic['pubTime'] = int(worker.publishTime.replace('.','')+'0')
                    worker_dic['distance'] = Distance(user.Location_lati, user.Location_longi,
                                                      worker.Location_lati, worker.Location_longi)
                    # worker_dic['isVisible'] = True if UserVisible.objects.filter(user_payed=user.openId, user_visible=worker.openId) \
                    #                                 else False
                    worker_dic['isVisible'] = True
                    worker_dic['isRateble'] = worker_dic['isVisible']
                    worker_dic['phoneNum'] = worker.phonenum
                    worker_dic['portraitUrl'] = worker.avatarAddr
                    work_objects_db.append(worker_dic)
            # print work_objects_db
            # if sortByDis == 'true':
            #     work_objects_db = sorted(work_objects_db, key=lambda woker_dic: woker_dic['distance'])
            # elif sortByPubTime == 'true':
            #     work_objects_db = sorted(work_objects_db, key=lambda woker_dic: woker_dic['pubTime'])
            work_objects = work_objects_db
            p = Paginator(work_objects, 10)  # 3条数据为一页，实例化分页对象
            #print p.count  # 10 对象总共10个元素
            print p.num_pages  # 4 对象可分4页
            #print p.page_range  # xrange(1, 5) 对象页的可迭代范围

            page_object = p.page(page)  # 取对象的第一分页对象
            conten_dict = {
                "totalNum": p.count,
                "perNum": 5,
                "totalPage": p.num_pages,
                "currentPage": page,
                "listData": page_object.object_list
            }
            print conten_dict
            return HttpResponse(json.dumps(conten_dict))
        else:
            return HttpResponse("wrong parameters!")


#@login_required
def transaction(request):
    if request.method == 'GET':
        openid = request.GET.get('openid')
        if openid:
            data = {}
            data['openid'] = openid
            return render(request, 'transaction.html', data)


def transaction_ajax(request):
    if request.method == 'POST':
        print request.POST
        openid = request.POST.get('openid')
        sortByDis =request.POST.get('sortByDis')
        sortByPubTime = request.POST.get('sortByPubTime')
        page = request.POST.get('page')
        # openid = 'oT69X1Chvefxgv3wby_-PaEIM9nY'
        if openid:
            print "i get openid here 448 line :" + openid
            listData = []
            user_transactions = UserVisible.objects.filter(user_payed=openid)
            for tansaction_item in user_transactions:
                transation_dic = {}
                transation_dic['billid'] = tansaction_item.transation_no
                transation_dic['transcationTime'] = int(tansaction_item.request_time.replace('.', '')+'0')
                transation_dic['transcationType'] = u'查看扣款'
                transation_dic['transcationMoney'] = -50
                listData.append(transation_dic)
        p = Paginator(listData, 3)  # 3条数据为一页，实例化分页对象
        # print p.count  # 10 对象总共10个元素
        print p.num_pages  # 4 对象可分4页
        # print p.page_range  # xrange(1, 5) 对象页的可迭代范围

        page_object = p.page(page)  # 取对象的第一分页对象
        conten_dict = {

            "listData": page_object.object_list
        }
        print conten_dict
        return HttpResponse(json.dumps(conten_dict))


def worklist_ajax(request):
    if request.method == 'POST':

        openid = request.POST.get('openid')
        sortByDis =request.POST.get('sortByDis')
        sortByPubTime = request.POST.get('sortByPubTime')
        page = request.POST.get('page')
        perNum = 10
        # openid = 'oT69X1Chvefxgv3wby_-PaEIM9nY'
        if openid:
            user = UserProfileBase.objects.filter(openId=openid).first()
            tag_list = list(user.Jobs.copy())
            # 查询该用户支付过的记录
            payed_list = [payed_user.user_visible for payed_user in UserVisible.objects.filter(user_payed=openid,pay_status='payed')]


            work_objects_db = []
            if len(tag_list) >= 2:
                filter_query = reduce(lambda x, y: Q(Jobs__contains=x) | Q(Jobs__contains=y), tag_list)
            else:
                filter_query = Q(Jobs__contains=tag_list[0])

            workers = UserProfileBase.objects.exclude(Role=user.Role).filter(filter_query). \
                filter(Location_longi__range=(user.Location_longi - 10, user.Location_longi + 10)). \
                filter(Location_lati__range=(user.Location_lati - 10, user.Location_lati + 10)).filter(online=True)

            for worker in workers:
                worker_dic = dict()
                # 添加sharable参数给前端做是否可分享判断ß
                if r.get(openid):
                    worker_dic['sharable'] = False
                else:
                    worker_dic['sharable'] = True

                worker_dic['userid'] = worker.id
                worker_dic['username'] = worker.userName
                worker_dic['tag'] = list(worker.Jobs)
                #worker_dic['star'] = int(worker.Score)
                worker_dic['star'] = int(worker.Score)
                # 老板要改成登录时间
                if not worker.last_login2:
                    logger.error("%s has no last_login2 value"%worker.phonenum)
                    continue
                worker_dic['pubTime'] = int(worker.last_login2.replace('.', '') + '0')
                #worker_dic['pubTime'] = int(worker.publishTime.replace('.','')+'0')
                worker_dic['distance'] = Distance(user.Location_lati, user.Location_longi, worker.Location_lati, worker.Location_longi)
                # worker_dic['isVisible'] = True if UserVisible.objects.filter(user_payed=user.openId, user_visible=worker.openId) \
                #                                 else False
                worker_dic['isVisible'] = True if worker.openId in payed_list else False
                worker_dic['isRateble'] = worker_dic['isVisible']
                worker_dic['phoneNum'] = worker.phonenum if worker_dic['isVisible'] else "123456789123"
                worker_dic['portraitUrl'] = worker.avatarAddr
                work_objects_db.append(worker_dic)
            # work_objects_db = list(set(work_objects_db))
            # print work_objects_db
            if sortByDis == 'true':
                work_objects_db = sorted(work_objects_db, key=lambda woker_dic: woker_dic['distance'])
            elif sortByPubTime == 'true':
                work_objects_db = sorted(work_objects_db, key=lambda woker_dic: woker_dic['pubTime'])
            work_objects = work_objects_db
            p = Paginator(work_objects, perNum)  # 3条数据为一页，实例化分页对象
            #print p.count  # 10 对象总共10个元素

            #print p.page_range  # xrange(1, 5) 对象页的可迭代范围

            page_object = p.page(page)  # 取对象的第一分页对象
            conten_dict = {
                "totalNum": p.count,
                "perNum": perNum,
                "totalPage": p.num_pages,
                "currentPage": page,
                "listData": page_object.object_list
            }
            return HttpResponse(json.dumps(conten_dict))
        else:
            return HttpResponse("wrong parameters!")


def render_js_config(request):
    data = {}
    data['openid'] = request.GET.get('openid')
    data['timestamp'] = int(time.time())
    data['nonceStr'] = 'qujunqujun'
    data['appid'] = WEIXIN_APPID
    data['jsapi_ticket'] = get_jsapi_token()
    data['url'] = request.build_absolute_uri()
    jsapi_string = "jsapi_ticket={JSAPI_TICKET}&noncestr={NONCESTR}&timestamp={TIMESTAMP}&url={URL}". \
        format(JSAPI_TICKET=data['jsapi_ticket'], NONCESTR=data['nonceStr'], TIMESTAMP=data['timestamp'],
               URL=data['url'])
    data['signature'] = hashlib.sha1(jsapi_string).hexdigest()

    return data


def wxpay_notify(request):
    return_str = """
    <xml>
      <return_code><![CDATA[SUCCESS]]></return_code>
      <return_msg><![CDATA[OK]]></return_msg>
    </xml>
    """
    if request.method == 'POST':
        _xml = request.body
        # 拿到微信发送的xml请求 即微信支付后的回调内容
        xml = str(_xml)
        print("xml", xml)
        return_dict = {}
        tree = et.fromstring(xml)
        # xml 解析
        return_code = tree.find("return_code").text
        try:
            if return_code == 'FAIL':
                # 官方发出错误
                return_dict['message'] = '支付失败'
                # return Response(return_dict, status=status.HTTP_400_BAD_REQUEST)
            elif return_code == 'SUCCESS':
                # 拿到自己这次支付的 out_trade_no
                _out_trade_no = tree.find("out_trade_no").text
                print "qujun:debug in views 453line!!!  zhifu pay success!!!"
                print _out_trade_no
                User_view_pay = UserVisible.objects.filter(transation_no=_out_trade_no).first()
                User_view_pay.payed_time = time.time()
                User_view_pay.pay_status = 'payed'
                User_view_pay.save()

                # 这里省略了 拿到订单号后的操作 看自己的业务需求

        except Exception as e:
            pass
        finally:
            return HttpResponse(return_str, status=200)


def moment_shared_notify(request):

    if request.method == "POST":
        try:
            # 支付者id
            openid = request.POST.get('openid')
            # 被查看者id
            userid = request.POST.get('userid')
            out_trade_no = time.strftime('%Y%m%d%M%S', time.localtime(time.time())) + "".join(
                random.choice(CHAR) for _ in range(5))
            useropenid = UserProfileBase.objects.filter(id=userid).first().openId

            User_view_pay = UserVisible(transation_no=out_trade_no, user_payed=openid, user_visible=useropenid,
                                        pay_status='payed', request_time=time.time())
            sign = "momentshared"+str(time.time())
            User_view_pay.paysign = sign
            User_view_pay.save()

            # 设置分享限制，在redis中写入该openid做标记
            today = datetime.date.today()
            tomorrow = today + datetime.timedelta(days=1)
            tomorrow_0630 = datetime.datetime(tomorrow.year, tomorrow.month, tomorrow.day, 1, 0, 0)
            r.set(name=openid, value=useropenid)
            r.expireat(openid, tomorrow_0630)
            return HttpResponse(json.dumps({"sign": sign}))
        except Exception, e:
            logger.error("moment_shared_notify error: %s", e)
            return HttpResponse("Wrong")


def zhihu_pre(request):
    if request.META.has_key('HTTP_X_FORWARDED_FOR'):
        ip = request.META['HTTP_X_FORWARDED_FOR']
    else:
        ip = request.META['REMOTE_ADDR']
    print "qujun zhihu_pre line 448!!!!!"
    print request.POST
    # 支付者id
    openid = request.POST.get('openid')
    # 被查看者id
    userid = request.POST.get('userid')
    body = request.POST.get('body') or u'查看电话'
    useropenid = UserProfileBase.objects.filter(id=userid).first().openId

    out_trade_no = time.strftime('%Y%m%d%M%S',time.localtime(time.time()))+"".join(random.choice(CHAR) for _ in range(5))


    wx_pay = WxPay(
        wx_app_id=WEIXIN_APPID,  # 微信平台appid
        wx_mch_id=ZHIHU_ID,  # 微信支付商户号
        wx_mch_key=ZHIHU_KEY,
        # wx_mch_key 微信支付重要密钥，请登录微信支付商户平台，在 账户中心-API安全-设置API密钥设置
        wx_notify_url='http://ewosugong.com/wxpay/notify/'
        # wx_notify_url 接受微信付款消息通知地址（通常比自己把支付成功信号写在js里要安全得多，推荐使用这个来接收微信支付成功通知）
        # wx_notify_url 开发详见https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=9_7
    )

    try:
        pay_data = wx_pay.js_pay_api(
            openid=openid,
            body=body,
            total_fee=100,
            out_trade_no=out_trade_no,
            spbill_create_ip=ip
        )
        User_view_pay = UserVisible(transation_no=out_trade_no, user_payed=openid, user_visible=useropenid,
                                    pay_status='prepay', request_time=time.time())
        User_view_pay.paysign = pay_data.get('sign', "wrongkey")
        User_view_pay.save()
        return HttpResponse(json.dumps(pay_data))
        # 订单生成后将请将返回的json数据 传入前端页面微信支付js的参数部分
        # print jsonify(pay_data)
    except WxPayError, e:
        logge.error("WxPayError: %s",e.message)
        return HttpResponse("zhifu some thing wrong!")


def dail(request):
    print request.GET
    openid = request.GET.get('openid')
    paysign = request.GET.get('paySign')
    User_view_pay = UserVisible.objects.filter(user_payed=openid,paysign=paysign).first()
    show_user = UserProfileBase.objects.filter(openId=User_view_pay.user_visible).first()

    phone_num = show_user.phonenum
    headimgurl = show_user.avatarAddr
    username = show_user.userName
    #print {'phone_num': phone_num,'headimgurl':headimgurl,'username':username}
    data = {'phone_num': phone_num, 'headimgurl': headimgurl, 'username': username, 'openid': openid}

    return render(request, 'dail.html', data)


def verify_code(request):
    phoneNum = request.POST.get('phoneNum')
    __business_id = uuid.uuid1()
    REGION = "cn-hangzhou"
    PRODUCT_NAME = "Dysmsapi"
    DOMAIN = "dysmsapi.aliyuncs.com"

    if request.META.has_key('HTTP_X_FORWARDED_FOR'):
        ip = request.META['HTTP_X_FORWARDED_FOR']
    else:
        ip = request.META['REMOTE_ADDR']
    request_time = time.time()

    ip_request_times = len(verify_code_request.objects.filter(request_ip=ip))
    if ip_request_times > 10:
        logger.error("evoke spm control")
        str_return = {"success": "false", "Code": "TOO_MANY"}
        return HttpResponse(str_return)
    verify_request = verify_code_request(request_ip=ip, request_phonenum=phoneNum, request_time=request_time)
    verify_request.save()
    acs_client = AcsClient(SMS_ACCESS_KEY_ID, SMS_ACCESS_KEY_SECRET, REGION)
    region_provider.add_endpoint(PRODUCT_NAME, REGION, DOMAIN)

    def send_sms(business_id, phone_numbers, sign_name, template_code, template_param=None):
        smsRequest = SendSmsRequest.SendSmsRequest()
        # 申请的短信模板编码,必填
        smsRequest.set_TemplateCode(template_code)

        # 短信模板变量参数
        if template_param is not None:
            smsRequest.set_TemplateParam(template_param)

        smsRequest.set_OutId(business_id)

        smsRequest.set_SignName(sign_name)

        smsRequest.set_PhoneNumbers(phone_numbers)

        smsResponse = acs_client.do_action_with_exception(smsRequest)

        return smsResponse
    code = random.randint(1000, 9999)

    params = "{\"code\":\"%s\"}"%(code)
    sms_return_string = send_sms(__business_id, phoneNum, "E我速工", "SMS_135675002", params)
    sms_return_dic = json.loads(sms_return_string)
    logger.info("sms return for verify code: %s", sms_return_dic)
    if sms_return_dic['Code'] == 'OK':
        request.session['verify_code'] = str(code)
        request.session['verify_code_time'] = request_time
        return HttpResponse({"success":"true","Code":0})
    else:
        return HttpResponse({"success": "false", "Code": sms_return_dic['Code']})


def complain(request):
    # TODO
    return HttpResponse("OK")


def rate(request):
    if request.method == "POST":
        userid = request.POST.get('userid')
        rateVal = request.POST.get('rateVal')
        if userid and rateVal:
            rateed_user = UserProfileBase.objects.filter(id=userid).first()
            rateed_user.ScoreCount += 1

            score = (rateed_user.Score*(rateed_user.ScoreCount-1)+int(rateVal))/float(rateed_user.ScoreCount)
            rateed_user.Score = score
            rateed_user.save()
            return HttpResponse("OK")
        else:
            return HttpResponse("wrong parameters!")


def nearby_jobs(request):
    if request.method == 'GET':
        data = {}
        data['openid'] = request.GET.get('openid')
        data['timestamp'] = int(time.time())
        data['nonceStr'] = 'qujunqujun'
        data['appid'] = WEIXIN_APPID
        data['jsapi_ticket'] = get_jsapi_token()
        data['url'] = request.build_absolute_uri()
        jsapi_string = "jsapi_ticket={JSAPI_TICKET}&noncestr={NONCESTR}&timestamp={TIMESTAMP}&url={URL}".\
            format(JSAPI_TICKET=data['jsapi_ticket'],NONCESTR=data['nonceStr'], TIMESTAMP=data['timestamp'], URL=data['url'])

        data['signature'] = hashlib.sha1(jsapi_string).hexdigest()

        data['jobList'] = []

        jobcates = Jobcates.objects.all()
        for jobcate in jobcates:

            job_dic = {'title': jobcate.jobcate, 'value': jobcate.id}
            data['jobList'].append(job_dic)
        data['jobList'] = json.dumps(data['jobList'])
        print "qujun RENDER jsapi data!!!!!!!!!!!!!"
        print data
        return render(request, 'jobs_nearby.html', data)

    elif request.method == 'POST':

        POST_DATA = request.POST
        openid = POST_DATA.get('openid')
        if not None in POST_DATA.values() and openid:
            if POST_DATA.get('online') == 'true':
                print "qujun : update database for jobs choose!!!"
                print request.POST
                user = UserProfileBase.objects.filter(openId=openid).first()
                user.Jobs = POST_DATA.get('tag')
                user.Location_lati = POST_DATA.get('latitude')
                user.Location_longi = POST_DATA.get('longitude')
                user.online = 'True'
                user.publishTime = time.time()
                user.save()

                return HttpResponse("OK")

            else:
                print "qujun : update database for jobs OFFline!!!"
                data = {}
                data['openid'] = openid
                user = UserProfileBase.objects.filter(openId=openid).first()
                user.online = 'False'
                user.save()

                return render(request, 'jobs.html', data)


        else:
            callbackurl = "/register/?openid={openid}".format(openid=openid)
            return HttpResponseRedirect(callbackurl)


def nearby_workers(request):
    if request.method == 'GET':
        openid = request.GET.get('openid')
        data = {}
        data['openid'] = request.GET.get('openid')
        data['timestamp'] = int(time.time())
        data['nonceStr'] = 'qujunqujun'
        data['appid'] = WEIXIN_APPID
        data['jsapi_ticket'] = get_jsapi_token()
        data['url'] = request.build_absolute_uri()
        jsapi_string = "jsapi_ticket={JSAPI_TICKET}&noncestr={NONCESTR}&timestamp={TIMESTAMP}&url={URL}".\
            format(JSAPI_TICKET=data['jsapi_ticket'],NONCESTR=data['nonceStr'], TIMESTAMP=data['timestamp'], URL=data['url'])

        data['signature'] = hashlib.sha1(jsapi_string).hexdigest()

        data['openid'] = openid
        user = UserProfileBase.objects.filter(openId=openid).first()
        data['role'] = user.Role
        return render(request, 'nearby.html', data)


def nearby_ajax(request):
    if request.method == "POST":
        logger.info("i am /nearby_ajax/!!!")
        print request.POST
        openid = request.POST.get('openid')
        sortByDis = request.POST.get('sortByDis')
        sortByPubTime = request.POST.get('sortByPubTime')
        page = request.POST.get('page')
        worker_radius = request.POST.get('radius')
        tag_list = [request.POST.get('filterTag')]
        perNum = 10
        if openid:
            user = UserProfileBase.objects.filter(openId=openid).first()
            # tag_list = list(user.Jobs.copy())
            # 查询该用户支付过的记录
            payed_list = [payed_user.user_visible for payed_user in
                          UserVisible.objects.filter(user_payed=openid, pay_status='payed')]


            work_objects_db = []
            if len(tag_list) >= 2:
                filter_query = reduce(lambda x, y: Q(Jobs__contains=x) | Q(Jobs__contains=y), tag_list)
            else:
                if tag_list[0] == u'\u5168\u90e8':
                    filter_query = ''
                else:
                    filter_query = Q(Jobs__contains=tag_list[0])
            if filter_query:

                workers = UserProfileBase.objects.exclude(Role=user.Role).filter(filter_query). \
                    filter(Location_longi__range=(user.Location_longi - 0.1, user.Location_longi + 0.1)). \
                    filter(Location_lati__range=(user.Location_lati - 0.1, user.Location_lati + 0.1)).filter(online=True)
            else:
                workers = UserProfileBase.objects.exclude(Role=user.Role).\
                    filter(Location_longi__range=(user.Location_longi - 0.1, user.Location_longi + 0.1)). \
                    filter(Location_lati__range=(user.Location_lati - 0.1, user.Location_lati + 0.1)).filter(online=True)

            for worker in workers:
                worker_dic = {}
                logger.info("nearby return here!!!")
                if r.get(openid):
                    worker_dic['sharable'] = False
                else:
                    worker_dic['sharable'] = True
                worker_dic['userid'] = worker.id
                worker_dic['username'] = worker.userName
                worker_dic['tag'] = list(worker.Jobs)
                # worker_dic['star'] = int(worker.Score)
                worker_dic['star'] = int(worker.Score)
                # 老板要改成登录时间
                if not worker.last_login2:
                    logger.error("%s has no last_login2 value"%worker.phonenum)
                    continue
                worker_dic['pubTime'] = int(worker.last_login2.replace('.', '') + '0')
                #worker_dic['pubTime'] = int(worker.publishTime.replace('.', '') + '0')
                worker_dic['distance'] = Distance(user.Location_lati, user.Location_longi, worker.Location_lati,
                                                  worker.Location_longi)
                # worker_dic['isVisible'] = True if UserVisible.objects.filter(user_payed=user.openId, user_visible=worker.openId) \
                #                                 else False
                worker_dic['isVisible'] = True if worker.openId in payed_list else False
                worker_dic['isRateble'] = worker_dic['isVisible']
                worker_dic['phoneNum'] = worker.phonenum if worker_dic['isVisible'] else "123456789123"
                worker_dic['portraitUrl'] = worker.avatarAddr
                if float(worker_dic['distance']) < float(worker_radius):
                    work_objects_db.append(worker_dic)
            # work_objects_db = list(set(work_objects_db))
            # print work_objects_db
            if sortByDis == 'true':
                work_objects_db = sorted(work_objects_db, key=lambda woker_dic: woker_dic['distance'])
            elif sortByPubTime == 'true':
                work_objects_db = sorted(work_objects_db, key=lambda woker_dic: woker_dic['pubTime'])
            work_objects = work_objects_db
            p = Paginator(work_objects, perNum)  # 3条数据为一页，实例化分页对象
            # print p.count  # 10 对象总共10个元素
            print p.num_pages  # 4 对象可分4页
            # print p.page_range  # xrange(1, 5) 对象页的可迭代范围

            page_object = p.page(page)  # 取对象的第一分页对象
            conten_dict = {
                "totalNum": p.count,
                "perNum": perNum,
                "totalPage": p.num_pages,
                "currentPage": page,
                "listData": page_object.object_list
            }

            return HttpResponse(json.dumps(conten_dict))
        else:
            return HttpResponse("wrong parameters!")

    else:
        return HttpResponse("wrong request method!!")


def change_username(request):
    if request.method == 'POST':
        openid = request.POST.get('openid')
        user = UserProfileBase.objects.filter(openId=openid).first()
        user.userName = request.POST.get('username')
        user.save()
        callbackurl = "/profile/?openid={openid}".format(openid=openid)
        return HttpResponseRedirect(callbackurl)


def shareCode(request):
    if request.method == 'GET':
        data = {}
        return render(request, 'shareCode.html', data)

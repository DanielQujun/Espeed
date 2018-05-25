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
from django.core.paginator import Paginator
from wx_pay import WxPay, WxPayError
from aliyunsdkcore.client import AcsClient
import uuid
from aliyunsdkcore.profile import region_provider
from aliyunsdkdysmsapi.request.v20170525 import SendSmsRequest


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

@csrf_exempt
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
        if request.GET.get('verify_code_wrong'):
            data['verify_code_wrong'] = request.GET.get('verify_code_wrong')
        data['openid'] = request.GET.get('openid')
        return render(request, 'login.html', data)

    elif request.method == 'POST':
        print "qujun:get register post!"
        print request.POST
        openid = request.POST.get('openid')
        phonenum = request.POST.get('phoneNum')
        veirycode = request.POST.get('signCode')
        if veirycode == request.session['verify_code'] and time.time() - request.session.get('verify_code_time') < 300:
            if phonenum and openid:

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
                    createTime=dt.now(),
                    last_login=dt.now(),
                )
                profile.save()
                callbackurl = "/role/?openid={openid}".format(openid=openid)
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
        openid = request.POST.get('openid')
        role = request.POST.get('role')
        if role and openid:

            user = UserProfileBase.objects.filter(openId=openid).first()
            user.role = role
            user.save()
            callbackurl = "/baseProfile/?openid={openid}".format(openid=openid)
            return HttpResponseRedirect(callbackurl)



def input_name(request):
    if request.method == 'GET':
        data = {}
        data['openid'] = request.GET.get('openid')

        # 准备根据openid来获取基本信息
        baseinfourl = BASEINFOURL.format(WEIXIN_ACCESS_TOKEN=get_access_token(), OPENID=data['openid'])
        resp, content = my_get(baseinfourl)
        user_info_dict = parse_Json2Dict(content)
        print user_info_dict

        return render(request, 'baseProfile.html', user_info_dict)
    elif request.method == 'POST':
        print "qujun: iam in inpurt name!"
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
            callbackurl = "/jobs/?openid={openid}".format(openid=POST_DATA.get('openid'))
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
        print "qujun RENDER jsapi data!!!!!!!!!!!!!"
        print data
        return render(request, 'jobs.html', data)

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
                callbackurl = "/workerList/?openid={openid}".format(openid=openid)
                return HttpResponse("OK")
                # return HttpResponseRedirect(callbackurl)
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
            #return HttpResponse('invalid post')

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
        print url
        resp, content = my_get(url)
        user_dict = parse_Json2Dict(content)
        print user_dict
    elif openid:
        user_dict['openid'] = openid
        user_dict['scope'] = "snsapi_userinfo"

    if user_dict['openid']:
        print "work list get openid is : "
        print user_dict['openid']
        user = UserProfileBase.objects.filter(openId=user_dict['openid']).first()
        if user is not None:
            print "user name is : "
            # 用户存在，判断用户是否是认证用户
            if user.fromUser.is_active:
                # 登录用户，其他任何途径都无法登录用户，后面使用装饰器验证用户是否登录来防止一些页面被用户直接访问

                # 取用户信息

                if user.phonenum:
                    if user.online:
                        print "qujun: User is  Online!"
                        data = render_js_config(request)
                        return render(request, 'workerList.html', data)
                    else:
                        print "qujun: User is Not Online!"
                        callbackurl = "/jobs/?openid={openid}".format(openid=user.openId)
                        return HttpResponseRedirect(callbackurl)


                else:
                    return HttpResponseRedirect('/register/')

            else:
                # 修改前台用来显示的文字
                showUrl = HOME_URL
                showText = "审核中，请等待..."
                print "qujun:审核中！！！"
                return HttpResponse(showText)
        else:

            callbackurl = "/register/?openid={openid}".format(openid=user_dict['openid'])
            return HttpResponseRedirect(callbackurl)
    else:
        print "user_dict 为空！！！！！"
        return HttpResponse('非法访问...')



#@login_required
def usercenter(request):
    return render(request, 'userCenter.html')
#@login_required
def profile(request):
    return render(request, 'profile.html')
#@login_required
def history(request):
    return render(request, 'history.html')
#@login_required
def transaction(request):
    return render(request, 'transaction')


def worklist_ajax(request):
    if request.method == 'POST':
        print request.POST
        openid = request.POST.get('openId')
        sortByDis =request.POST.get('sortByDis')
        sortByPubTime = request.POST.get('sortByPubTime')
        page = request.POST.get('page')
        # openid = 'oT69X1Chvefxgv3wby_-PaEIM9nY'
        user = UserProfileBase.objects.filter(openId=openid).first()
        tag_set = user.Jobs.copy()
        # 查询该用户支付过的记录
        payed_list = [payed_user.user_visible for payed_user in UserVisible.objects.filter(user_payed=openid)]
        print openid
        print "qujun debug views line 378!!! for payed_list"
        print payed_list

        work_objects_db = []
        for tag in tag_set:
            workers = UserProfileBase.objects.filter(Jobs__contains=tag)
            for worker in workers:
                print worker.openId
                worker_dic = {}
                worker_dic['userid'] = worker.id
                worker_dic['username'] = worker.userName
                worker_dic['tag'] = list(worker.Jobs)
                #worker_dic['star'] = int(worker.Score)
                worker_dic['star'] = 3
                worker_dic['pubTime'] = int(worker.publishTime.replace('.','')+'0')
                worker_dic['distance'] = Distance(user.Location_lati, user.Location_longi, worker.Location_lati, worker.Location_longi)
                # worker_dic['isVisible'] = True if UserVisible.objects.filter(user_payed=user.openId, user_visible=worker.openId) \
                #                                 else False
                worker_dic['isVisible'] = True if worker.openId in payed_list else False
                worker_dic['isRateble'] = worker_dic['isVisible']
                worker_dic['phoneNum'] = worker.phonenum
                worker_dic['portraitUrl'] = worker.avatarAddr
                work_objects_db.append(worker_dic)
        # print work_objects_db
        work_objects = work_objects_db
        p = Paginator(work_objects, 10)  # 3条数据为一页，实例化分页对象
        #print p.count  # 10 对象总共10个元素
        #print p.num_pages  # 4 对象可分4页
        #print p.page_range  # xrange(1, 5) 对象页的可迭代范围

        page_object = p.page(page)  # 取对象的第一分页对象
        conten_dict = {
            "totalNum": p.count,
            "perNum": 3,
            "totalPage": p.num_pages,
            "currentPage": page,
            "listData": page_object.object_list
        }
        print conten_dict
        return HttpResponse(json.dumps(conten_dict))



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
                print "qujun:debug in views 453line!!!"
                print _out_trade_no
                User_view_pay = UserVisible.objects.filter(transation_no=_out_trade_no).first()
                User_view_pay.status = 'payed'
                User_view_pay.save()

                # 这里省略了 拿到订单号后的操作 看自己的业务需求

        except Exception as e:
            pass
        finally:
            return HttpResponse(return_str, status=200)


def zhihu_pre(request):
    if request.META.has_key('HTTP_X_FORWARDED_FOR'):
        ip = request.META['HTTP_X_FORWARDED_FOR']
    else:
        ip = request.META['REMOTE_ADDR']
    print "qujun zhihu_pre line 448!!!!!"
    print request.POST
    # 支付者id
    openid = request.POST.get('openId')
    # 被查看者id
    userid = request.POST.get('userid')
    useropenid = UserProfileBase.objects.filter(id=userid).first().openId

    out_trade_no = time.strftime('%Y%m%d%M%S',time.localtime(time.time()))+"".join(random.choice(CHAR) for _ in range(20))

    User_view_pay = UserVisible(transation_no=out_trade_no,user_payed=openid,user_visible=useropenid,pay_status='prepay')


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
            body=u'商品',
            total_fee=1,
            out_trade_no=out_trade_no,
            spbill_create_ip=ip
        )
        User_view_pay.paysign = pay_data.get('sign', "wrongkey")
        User_view_pay.save()
        return HttpResponse(json.dumps(pay_data))
        # 订单生成后将请将返回的json数据 传入前端页面微信支付js的参数部分
        # print jsonify(pay_data)
    except WxPayError, e:
        print e.message, 400


def dail(request):
    print request.GET
    openid = request.GET.get('openid')
    paysign = request.GET.get('paySign')
    User_view_pay = UserVisible.objects.filter(user_payed=openid,paysign=paysign).first()
    phone_num = UserProfileBase.objects.filter(openId=User_view_pay.user_visible).first().phonenum

    return render(request, 'dail.html', {'phone_num': phone_num})

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
        print "evoke spm control"
        str_return = {"success":"false","Code":"TOO_MANY"}
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

        # 设置业务请求流水号，必填。
        smsRequest.set_OutId(business_id)

        # 短信签名
        smsRequest.set_SignName(sign_name)

        # 数据提交方式
        # smsRequest.set_method(MT.POST)

        # 数据提交格式
        # smsRequest.set_accept_format(FT.JSON)

        # 短信发送的号码列表，必填。
        smsRequest.set_PhoneNumbers(phone_numbers)

        # 调用短信发送接口，返回json
        smsResponse = acs_client.do_action_with_exception(smsRequest)

        return smsResponse
    code = random.randint(1000, 9999)

    params = "{\"code\":\"%s\"}"%(code)
    sms_return_string = send_sms(__business_id, phoneNum, "E我速工", "SMS_135675002", params)
    sms_return_dic = json.loads(sms_return_string)
    if sms_return_dic['Code'] == 'OK':
        request.session['verify_code'] = str(code)
        request.session['verify_code_time'] = request_time
        return HttpResponse({"success":"true","Code":0})
    else:
        return HttpResponse({"success": "false", "Code": sms_return_dic['Code']})
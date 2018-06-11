# encoding:utf-8
from xml.etree.ElementTree import Element,fromstring
from xml.etree.ElementTree import tostring
from xml.etree.ElementTree import dump
from datetime import datetime
from lxml import etree
import httplib2
import time
import random
import string
import hashlib
import json
from django.utils.encoding import smart_unicode

from django.utils.encoding import smart_str

import weixin.config
from weixin.config import REDIS_HOST,REDIS_PORT
from math import *

import redis
r = redis.Redis(host=REDIS_HOST,port=REDIS_PORT)


def Distance(lat1,lng1,lat2,lng2):# 第二种计算方法
    lat1 = float(lat1)
    lat2 = float(lat2)
    lng1 = float(lng1)
    lng2 = float(lng2)
    radlat1=radians(lat1)
    radlat2=radians(lat2)
    a=radlat1-radlat2
    b=radians(lng1)-radians(lng2)
    s=2*asin(sqrt(pow(sin(a/2),2)+cos(radlat1)*cos(radlat2)*pow(sin(b/2),2)))
    earth_radius=6378.137
    s=s*earth_radius*1000
    if s<0:
        return -s
    else:
        return s
# xml格式的字符串 ==》 字典
def parse_Xml2Dict(raw_xml):
    xmlstr = etree.fromstring(raw_xml)
    dict_xml = {}
    for child in xmlstr:
        dict_xml[child.tag] = child.text.encode(u'UTF-8')
    return dict_xml


# 字典 ==》 xml格式的字符串
def parse_Dict2Xml(tag, d):
    elem = Element(tag)
    for key, val in d.items():
        child = Element(key)
        child.text = str(val)
        elem.append(child)

    my_str = tostring(elem, encoding=u'UTF-8')
    return my_str


# json样式的str ==> dict
def parse_Json2Dict(my_json):
    my_dict = json.loads(my_json)
    return my_dict


# dict ==> json样式的str
def parse_Dict2Json(my_dict):
    my_json = json.dumps(my_dict, ensure_ascii=False)
    return my_json


def my_get(url):
    h = httplib2.Http()
    resp, content = h.request(url, 'GET')
    return resp, content


def my_post(url, data):
    h = httplib2.Http()
    resp, content = h.request(url, 'POST', data)
    return resp, content


def dictfetchall(cursor):
    "Returns all rows from a cursor as a dict"
    "将自定义sql返回的列表转为字典 http://python.usyiyi.cn/django/topics/db/sql.html#executing-custom-sql-directly"
    desc = cursor.description
    return [
        dict(zip([col[0] for col in desc], row))
        for row in cursor.fetchall()
    ]

def responseMsg(postContent):
    postStr = smart_str(postContent)
    if postStr:
        msg = xmlContent2Dic(postStr)
        if msg['MsgType']:
            if msg['MsgType'] == 'event':
                resultStr = handleEvent(msg)  #处理事件推送
        else:
            resultStr = 'Input something...'

    return resultStr

#函数把微信XML格式信息转换成字典格式
def xmlContent2Dic(xmlContent):
    dics = {}
    elementTree = fromstring(xmlContent)
    if elementTree.tag == 'xml':
        for child in elementTree:
            dics[child.tag] = smart_unicode(child.text)
    return dics

def handleEvent(msg):
    msg_content = u'您好，感谢关注“建工家”招工信息平台。[耶][耶][耶][耶][耶][耶][耶]'
    if msg['Event'] == 'subscribe':
        resultStr="<xml><ToUserName><![CDATA[%s]]></ToUserName><FromUserName><![CDATA[%s]]></FromUserName><CreateTime>%s</CreateTime><MsgType><![CDATA[%s]]></MsgType><Content><![CDATA[%s]]></Content></xml>"
        resultStr = resultStr % (msg['FromUserName'],msg['ToUserName'],str(int(time.time())),'text',msg_content)
    return resultStr


def get_access_token():
    WEIXIN_ACCESS_TOKEN = r.get('WEIXIN_ACCESS_TOKEN')
    if WEIXIN_ACCESS_TOKEN:
        return WEIXIN_ACCESS_TOKEN
    else:
        resp, result = my_get(weixin.config.WEIXIN_ACCESS_TOKEN_URL)
        decodejson = parse_Json2Dict(result)
        WEIXIN_ACCESS_TOKEN = str(decodejson[u'access_token'])
        WEIXIN_ACCESS_TOKEN_EXPIRES_IN = decodejson['expires_in']
        r.set(name='WEIXIN_ACCESS_TOKEN',value=WEIXIN_ACCESS_TOKEN,ex=WEIXIN_ACCESS_TOKEN_EXPIRES_IN-60)
        return WEIXIN_ACCESS_TOKEN



def get_access_token_bak():
    # 获取 access_token 存入 WEIXIN_ACCESS_TOKEN
    if weixin.config.WEIXIN_ACCESS_TOKEN_LASTTIME == 0 or (int(
            time.time()) - weixin.config.WEIXIN_ACCESS_TOKEN_LASTTIME > weixin.config.WEIXIN_ACCESS_TOKEN_EXPIRES_IN - 300):

        resp, result = my_get(weixin.config.WEIXIN_ACCESS_TOKEN_URL)
        decodejson = parse_Json2Dict(result)

        weixin.config.WEIXIN_ACCESS_TOKEN = str(decodejson[u'access_token'])
        weixin.config.WEIXIN_ACCESS_TOKEN_LASTTIME = int(time.time())
        weixin.config.WEIXIN_ACCESS_TOKEN_EXPIRES_IN = decodejson['expires_in']

        print "new access_token ->> " + weixin.config.WEIXIN_ACCESS_TOKEN + "---" + str(
            weixin.config.WEIXIN_ACCESS_TOKEN_LASTTIME) + "---" + str(weixin.config.WEIXIN_ACCESS_TOKEN_EXPIRES_IN)
        return weixin.config.WEIXIN_ACCESS_TOKEN
    else:
        print "old access_token ->> " + weixin.config.WEIXIN_ACCESS_TOKEN + "---" + str(
            weixin.config.WEIXIN_ACCESS_TOKEN_LASTTIME) + "---" + str(weixin.config.WEIXIN_ACCESS_TOKEN_EXPIRES_IN)
        return weixin.config.WEIXIN_ACCESS_TOKEN


def get_jsapi_token():
    JSAPI_TICKET = r.get('JSAPI_TICKET')
    if JSAPI_TICKET:
        return JSAPI_TICKET
    else:
        jsapi_url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token={ACCESS_TOKEN}&type=jsapi". \
            format(ACCESS_TOKEN=get_access_token())
        resp, content = my_get(jsapi_url)
        jsapi_ticket_dic = parse_Json2Dict(content)
        JSAPI_TICKET = str(jsapi_ticket_dic[u'ticket'])
        JSAPI_TICKET_EXPIRES_IN = jsapi_ticket_dic['expires_in']
        r.set(name='JSAPI_TICKET', value=JSAPI_TICKET, ex=JSAPI_TICKET_EXPIRES_IN-60)
        return JSAPI_TICKET


def get_jsapi_token_bak():
    if weixin.config.WEIXIN_ACCESS_TOKEN_LASTTIME == 0 or (int(
            time.time()) - weixin.config.WEIXIN_ACCESS_TOKEN_LASTTIME > weixin.config.WEIXIN_ACCESS_TOKEN_EXPIRES_IN - 300):
        jsapi_url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token={ACCESS_TOKEN}&type=jsapi". \
            format(ACCESS_TOKEN=get_access_token())
        resp, content = my_get(jsapi_url)
        jsapi_ticket_dic = parse_Json2Dict(content)
        weixin.config.JSAPI_TICKET = str(jsapi_ticket_dic[u'ticket'])
        weixin.config.JSAPI_TICKET_LASTTIME = int(time.time())
        weixin.config.JSAPI_TICKET_EXPIRES_IN = jsapi_ticket_dic['expires_in']

        print "new JSAPI_TICKET ->> " + weixin.config.JSAPI_TICKET + "---" + str(
            weixin.config.JSAPI_TICKET_LASTTIME) + "---" + str(weixin.config.JSAPI_TICKET_EXPIRES_IN)
        return weixin.config.JSAPI_TICKET
    else:
        print "old access_token ->> " + weixin.config.JSAPI_TICKET + "---" + str(
            weixin.config.JSAPI_TICKET_LASTTIME) + "---" + str(weixin.config.JSAPI_TICKET_EXPIRES_IN)
        return weixin.config.JSAPI_TICKET


def send_online_to_redis(username,openId, role, jobs, phonenum, location_lati, location_longi, publishtime):
    data_dic = {'username': username, 'openid':openId, 'role': role, 'jobs': jobs, 'phonenum': phonenum, 'location_lati': location_lati,
                'location_longi': location_longi, 'publishtime': publishtime}
    print json.dumps(data_dic)
    try:
        r.sadd('online_queue', json.dumps(data_dic))
    except Exception, e:
        print "send_online_to_redis FAILED"
        print e

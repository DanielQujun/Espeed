# encoding:utf-8
from xml.etree.ElementTree import Element
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

import weixin.config


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


def get_access_token():
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
#!/usr/bin/env python
#-*- coding:utf-8 -*-
import urllib2,json
import datetime,time
import sys
reload(sys)
sys.setdefaultencoding("utf-8")

import redis
r = redis.Redis(host='127.0.0.1',port='6379')

def get_access_token():
    WEIXIN_ACCESS_TOKEN = r.get('WEIXIN_ACCESS_TOKEN')
    if WEIXIN_ACCESS_TOKEN:
        return WEIXIN_ACCESS_TOKEN

class WechatPush():

  def post_data(self,url,para_dct):
    """触发post请求微信发送最终的模板消息"""
    para_data = para_dct
    f = urllib2.urlopen(url,para_data)
    content = f.read()
    print " i get weixin return content "
    return content

  def do_push(self,touser,url,template_id,data):
    # token = get_access_token()
    #最红post的求情数据
    dict_arr = {"touser": touser,
                "template_id": template_id,
                "url": url,
                "topcolor": "#FF0000",
                'data': data
                }
    json_template = json.dumps(dict_arr)
    print dict_arr
    requst_url = "https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=" + "10_TKYecyQpTMHPLAHcewrdrSBnlYzLk_os_JeM5pagSouHUkmOv70EpitEj8_AnLic9_6FwQ5uYvE4Ls7J8wsiNX35nLvejBOMVLtmikyYVOv5Hq0dLSGJuvkp6_MGLMeACAYDE"
    content = self.post_data(requst_url,json_template)
    #读取json数据
    j = json.loads(content)
    print j

if __name__ == "__main__":
    timestamp = time.time()
    openid = 'oT69X1NC-ZcQHgM2ERE4bRj-_pS4'
    username = u'张先生'
    phonenum = "1388****888"
    timestruct = time.localtime(timestamp)
    time_str = time.strftime('%Y-%m-%d %H:%M:%S', timestruct)


    wechatpush = WechatPush()
    touser = openid
    template_id = 'nNYHQN0U7Jvbb8ldc13ZxA1kAfzfPSo33D889RCra7k'
    url = "http://ewosugong.com/workerList/?openid={openid}&sorttime=true".format(openid=openid)
    data = {
            "first": {
            "value":"您关注的工种，有新的用户上线了",
            "color":"#173177"
            },
            "keyword1": {
                "value": username,
                "color": "#173177"
            },
            "keyword2":{
            "value": phonenum,
            "color":"#173177"
            },
            "remark":{
            "value": "快来查看下吧",
            "color": "#173177"
            },
        }
    wechatpush.do_push(touser=touser,url=url,template_id=template_id, data=data)

#!/usr/bin/env python
#-*- coding:utf-8 -*-
import urllib2,json
import datetime,time
import sys
import MySQLdb
reload(sys)
import traceback
sys.setdefaultencoding("utf-8")
from math import *
import redis
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


r = redis.Redis(host='127.0.0.1', port='6379')
r1 = redis.Redis(host='127.0.0.1', port='6379', db=1)


def Distance(lat1,lng1,lat2,lng2):# 第二种计算方法
    lat1 = float(lat1)
    lat2 = float(lat2)
    lng1 = float(lng1)
    lng2 = float(lng2)
    radlat1=radians(lat1)
    radlat2=radians(lat2)
    a=radlat1-radlat2
    b=radians(lng1)-radians(lng2)
    s = 2 * asin(sqrt(pow(sin(a/2), 2)+cos(radlat1)*cos(radlat2)*pow(sin(b/2),2)))
    earth_radius = 6378.137
    s = s * earth_radius * 1000
    if s < 0:
        return -s
    else:
        return s


def get_access_token():
    WEIXIN_ACCESS_TOKEN = r.get('WEIXIN_ACCESS_TOKEN')
    if WEIXIN_ACCESS_TOKEN:
        return WEIXIN_ACCESS_TOKEN
    else:
        logger.error("did not get WEIXIN_ACCESS_TOKEN")


class WechatPush():

  def post_data(self, url, para_dct):
    """触发post请求微信发送最终的模板消息"""
    para_data = para_dct
    f = urllib2.urlopen(url, para_data)
    content = f.read()
    logger.error(" i get weixin return content ")
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

    access_token = get_access_token()
    requst_url = "https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=" + access_token
    content = self.post_data(requst_url, json_template)
    #读取json数据
    j = json.loads(content)
    logger.error(j)


if __name__ == "__main__":

    while True:
        try:
            db = MySQLdb.connect("127.0.0.1", "root", "aaa@****.com", "sugong", charset='utf8')
            cursor = db.cursor()
            online_user = r.spop('online_queue')
            if online_user:
                logger.error("有人上线了")
                logger.error(online_user)
                online_user_dic = json.loads(online_user)
                jobs = online_user_dic.get('jobs').split(',')
                role = online_user_dic.get('role')
                user_set = set()
                for job in jobs:
                    sql = ' select * from weixin_userprofilebase where Jobs like "%{job}%" and role != {role} and online = 1;'.format(
                        job=job.encode('utf8'), role=role)
                    cursor.execute(sql)
                    subsci_user = cursor.fetchall()
                    user_set = user_set | set(subsci_user)

                for user in user_set:
                    user = list(user)
                    openid = user[2]
                    username = user[4]
                    Location_lati = user[11]
                    Location_longi = user[12]
                    phonenum = user[8][0:7]+"****"
                    jobs = user[15]
                    online = user[16]
                    wechatpush = WechatPush()
                    touser = openid
                    distnce = Distance(online_user_dic.get('location_lati'), online_user_dic.get('location_lati'),Location_lati,Location_longi)
                    logger.error("两者距离为%s"%distnce)
                    if online_user_dic['phonenum'] != user[8] and not r1.get(openid) and distnce < 10000000:
                        # 将已发送的用户插入redis队列，设置一天的过期时间
                        today = datetime.date.today()
                        tomorrow = today + datetime.timedelta(days=1)
                        tomorrow_0630 = datetime.datetime(tomorrow.year, tomorrow.month, tomorrow.day, 06, 30, 0)
                        r1.set(name=openid, value=username)
                        r1.expireat(openid, tomorrow_0630)
                        logger.error("给用户%s发送信息" %(username))
                        if role == 1:
                            value = "附近有适合你的专业技术工种"
                        else:
                            value = "附近有老板要找专业技术人员干活"

                        template_id = 'nNYHQN0U7Jvbb8ldc13ZxA1kAfzfPSo33D889RCra7k'
                        url = "http://ewosugong.com/workerList/?openid={openid}&sorttime=true".format(openid=openid)
                        data = {
                                "first": {
                                "value": value,
                                "color":"#173177"
                                },
                                "keyword1": {
                                    "value": username,
                                    "color": "#173177"
                                },
                                "keyword2": {
                                "value": phonenum,
                                "color":"#173177"
                                },
                                "remark":{
                                "value": "快来查看下吧",
                                "color": "#173177"
                                },
                            }
                        wechatpush.do_push(touser=touser, url=url, template_id=template_id, data=data)
            else:
                time.sleep(10)
        except Exception, e:

            logger.error(traceback.format_exc())
            logger.error("出错了")
            time.sleep(5)

        finally:
            db.close()

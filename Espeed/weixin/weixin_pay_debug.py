# coding: utf-8
from wx_pay import WxPay, WxPayError
from weixin.config import *
from hashlib import sha1
from time import time
import json

from flask import jsonify

wx_pay = WxPay(
    wx_app_id=WEIXIN_APPID,  # 微信平台appid
    wx_mch_id=ZHIHU_ID,  # 微信支付商户号
    wx_mch_key=ZHIHU_KEY,
    # wx_mch_key 微信支付重要密钥，请登录微信支付商户平台，在 账户中心-API安全-设置API密钥设置
    wx_notify_url='http://ewosugong.com/wxpay/notify'
    # wx_notify_url 接受微信付款消息通知地址（通常比自己把支付成功信号写在js里要安全得多，推荐使用这个来接收微信支付成功通知）
    # wx_notify_url 开发详见https://pay.weixin.qq.com/wiki/doc/api/jsapi.php?chapter=9_7
)

try:
    pay_data = wx_pay.js_pay_api(
        openid='oT69X1Chvefxgv3wby_-PaEIM9nY',  # 付款用户openid
        body=u'商品',  # 例如：饭卡充值100元
        total_fee=100,  # total_fee 单位是 分， 100 = 1元
        spbill_create_ip='47.104.175.181'    # 若不使用flask框架，则需要传入调用微信支付的用户ip地址
    )
    print pay_data
    print json.dumps(pay_data)
    # 订单生成后将请将返回的json数据 传入前端页面微信支付js的参数部分
    #print jsonify(pay_data)
except WxPayError, e:
    print e.message, 400
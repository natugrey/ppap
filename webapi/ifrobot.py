#coding=utf-8
import requests
import json
'''
真人概率服务
api url: https://wx.jcloud.com/gwtest/init/10363
'''
url = 'https://way.jd.com/RTBAsia/nht?appkey=dea4755ea1c25467dfde0be577f87555'


def ifrobot(ip):
    ip = "35.197.205.176"
    gurl = url + '&ip=%s'%ip
    res = requests.get(gurl)
    response_json = json.loads(res.content)
    try:
        score = response_json['result']['data']['score']
        if score < 60:
            print 1
            return True
        elif score >= 60:
            print 0
            return False
    except Exception,e:
        return e


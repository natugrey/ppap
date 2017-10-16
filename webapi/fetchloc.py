#coding=utf-8
import requests
from config import BAIDU_AK, GAODE_KEY
'''
高精度地理位置服务
'''
baidu_url = 'http://api.map.baidu.com/location/ip'

'''
baidu api: http://lbsyun.baidu.com/index.php?title=webapi/ip-api
'''
def fetchloc1(ip):
    gurl = baidu_url + '?coor=bd09ll&ak=%s&ip=%s'%(BAIDU_AK, ip)
    print gurl
    res  = requests.get(gurl)
    print res.content.decode('unicode-escape')
    return

'''
gaode api url:http://lbs.amap.com/api/webservice/guide/api/ipconfig/?
'''
gaode_url = 'http://restapi.amap.com/v3/ip'
def fetchloc2(ip):
    gurl = gaode_url + '?output=json&key=%s&ip=%s'%(GAODE_KEY, ip)
    print gurl
    res = requests.get(gurl)
    print res.content
    return

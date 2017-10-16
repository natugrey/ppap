#coding=utf-8
import requests

url = 'https://www.abuseipdb.com/check/'
url2 = 'https://www.abuseipdb.com/report/json?'
API_KEY = '2HwugmLnnW3uv8KEcvLPoL8u6kDG1PGF8fy4VhUp'

def ipcheck(ip, days):
    gurl = url + '%s/json?key=%s&days=%s'%(ip, API_KEY, days)
    res = requests.get(gurl)
    print res.content
def ipreport(ip, categories, comment):
    gurl = url2 + 'key=%s&category=%s&comment=%s&ip=%s'%(API_KEY, categories, comment, ip)
    res = requests.get(gurl)
    print res.content
# ipreport('82.165.37.26', '10,11,14','')
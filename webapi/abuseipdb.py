#coding=utf-8
import requests
import re
'''
categories : https://www.abuseipdb.com/categories
'''
category = {'3': 'Fraud Orders',
            '4': 'DDoS Attack',
            '9': 'Open Proxy',
            '10': 'Web Spam',
            '11': 'Email Spam',
            '14': 'Port Scan',
            '18': 'Brute-Force',
            '19': 'Bad Web Bot',
            '20': 'Exploited Host',
            '21': 'Web App Attack',
            '22': 'SSH',
            '23': 'IoT Targeted'}

url = 'https://www.abuseipdb.com/check/'
API_KEY = '2HwugmLnnW3uv8KEcvLPoL8u6kDG1PGF8fy4VhUp'

def ipcheck(ip):
    gurl = url + '%s/json?key=%s'%(ip, API_KEY)
    res = requests.get(gurl)
    # print res.content
    # data = []
    data = dataformat(res.content)
    # print data
    return data
'''
data = [{'dns':dns, 'info': info},
        ...
        ]
'''
def dataformat(content):
    data = []
    dict = {'dns':''}
    list = re.findall('\[([\d,]+)]', content)
    # print list
    for x in list:
        nums = re.findall('\d+', x)
        for y in nums:
            if category.has_key(y):
                if not dict.has_key('info'):
                    dict['info'] = category[y] + ';'
                else:
                    dict['info'] = dict['info'] + category[y] + ';'
        if dict.has_key('info'):
            data.append(dict)
            dict = {'dns': ''}
    return data

# ipcheck('88.211.129.250')


#coding=utf-8
import requests

'''
categories : https://www.abuseipdb.com/categories
'''
category = {3: 'Fraud Orders',
            4: 'DDoS Attack',
            9: 'Open Proxy',
            10: 'Web Spam',
            11: 'Email Spam',
            14: 'Port Scan',
            18: 'Brute-Force',
            19: 'Bad Web Bot',
            20: 'Exploited Host',
            21: 'Web App Attack',
            22: 'SSH',
            23: 'IoT Targeted'}

url = 'https://www.abuseipdb.com/check/'
API_KEY = '2HwugmLnnW3uv8KEcvLPoL8u6kDG1PGF8fy4VhUp'

def ipcheck(ip):
    gurl = url + '%s/json?key=%s'%(ip, API_KEY)
    res = requests.get(gurl)
    print res.content

ipcheck('88.211.129.250')


#coding=utf-8
import requests
import re

url = 'https://x.threatbook.cn/ip/'
headers = {'Host': 'x.threatbook.cn',
           'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0',
           'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
           'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
           'Accept-Encoding': 'gzip, deflate, br'}

def scanip(ip):
    play_flash = 'query_item=%s'%ip
    gurl = url + ip
    cookies = {}
    cookies['PLAY_FLASH'] = play_flash
    res = requests.get(gurl, headers=headers, cookies=cookies)
    intelli = re.match('[\d\D]+<table class="table hidden table-vertical" id="intelli_table">([\D\d]+?)</table>', res.content).group(1)
    intelli_list = []
    listhead = ['intelli_source', 'discovery_time', 'intelli_type']
    intelli_list.append(listhead)
    records = re.findall('<td>[\d\D]+?</td>', intelli)
    count = 1
    tmptup = []
    for x in records:
        info = re.match('<td>(.+)</td>', x).group(1)
        if count%3 != 0:
            tmptup.append(info)
        else:
            intelli_list.append(tmptup)
            tmptup = []
            tmptup.append(info)
        count += 1
    return intelli_list

scanip('82.165.37.26')

'''
other services
'''
# url1 = 'https://x.threatbook.cn/api/v1/file/scan'
# url2 = 'https://x.threatbook.cn/api/v1/file/report'
# url3 = 'https://x.threatbook.cn/api/v1/file/rescan'
# url4 = 'https://x.threatbook.cn/api/v1/ip/query'
# API_KEY = '591b5212645e42c58a026d6bf9af4fa635224285fe804bc789d7de945b7553e2'
# headers = {'Host': 'x.threatbook.cn'
#            }
# def uploadfile():
#     params = {'apikey': API_KEY}
#     files = {'file': ('sample.txt', open('sample.txt', 'rb'),'multipart/form-data')}
#     res = requests.post(url1, data=params, files=files)
#     response_json = json.loads(res.content)
#     print response_json['scan_id']
#     return response_json
# #
# def scaninfo(scanid):
#     params = {'apikey': API_KEY,
#               'resource': scanid}
#     res = requests.post(url2, data= params)
#     print res.content
#
# def rescan(md5):
#     params = {'apikey': API_KEY,
#               'resource': md5}
#     res = requests.post(url3, data=params)
#     print res.content
#
# def scanip(ip):
#     params = {'apikey' : API_KEY,
#               'ip': ip,
#               'field': 'intelligences,judgments'}
#     res = requests.post(url4, data = params)
#     print res.content

# scanip('82.165.37.26')

# uploadfile()
# scanid = 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3-1505121378885'
# md5 = '202cb962ac59075b964b07152d234b70'
# response_json = testuploadfile()
# scanid = response_json['scan_id']
# md5 = response_json['md5']
# testscaninfo(scanid)
# testrescan(md5)



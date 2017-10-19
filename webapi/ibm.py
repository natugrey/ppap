import requests

url = 'https://api.xforce.ibmcloud.com/auth/api_key'
url1 = 'https://api.xforce.ibmcloud.com/resolve/'
API_KEY = '22a716dc-0f3a-428d-9012-3c5f75f0223a'
API_PASSWD = '470706cd-1736-4813-a0f9-d806695cd97f'

headers = {'Accept': 'application/json'}
params = {'apikey': API_KEY,
          'password': API_PASSWD}
session = requests.session()

def getauthentication():
    res = session.get(url, params=params)
    print res.content

def ipreverse(ip):
    gurl = url + ip
    res = requests.get(url1, params=params)
    print res.content

'''
data = [{'dns':dns, 'info': info},
        ...
        ]
'''
def dataformat(content):
    data = []
    return data
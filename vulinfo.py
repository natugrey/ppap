#coding=utf-8

from webapi.alienvault import scanipv4
from webapi.abuseipdb import ipcheck
from webapi.threatbook import scanip
from webapi.fetchloc import fetchloc1, fetchloc2
from webapi.ifrobot import ifrobot

'''
vulinfo = {'ip': [['type1','type2'],{'description': description, 'dns': dns}, {'description':...}...],
            ...
           }
'''

def getvulinfo(iplist):
    vulinfo = {}
    list = []
    descriptions = []
    dns = []
    for key in iplist:
        for x in iplist[key]:
            list.append(iplist[key][1])
            for y in scanipv4(key):
                descriptions.append(y['info'])
                dns.append(y['dns'])
            for y in scanip(key):
                descriptions.append(y['info'])
                dns.append(y['dns'])
            for y in ipcheck(key):
                descriptions.append(y['info'])
                dns.append(y['dns'])
            list.append(descriptions)
            list.append(dns)
            vulinfo[key] = list
            list = []
    # print vulinfo
    return vulinfo

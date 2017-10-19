#coding=utf-8

from webapi.alienvault import scanipv4
from webapi.abuseipdb import ipcheck
from webapi.threatbook import scanip
from webapi.fetchloc import fetchloc1, fetchloc2
from webapi.ifrobot import ifrobot

'''
vulinfo = {'ip': [type,{'description': description, 'dns': dns}, {'description':...}...],
            ...
           }
'''

def getvulinfo(iplist):
    vulinfo = {}
    list = []
    for key in iplist:
        for x in iplist[key]:
            list.append(iplist[key][1])
            for y in scanipv4(key):
                list.append(y)
            for y in scanip(key):
                list.append(y)
            for y in ipcheck(key):
                list.append(y)
            vulinfo[key] = list
            list = []
    print vulinfo
    return vulinfo

#coding=utf-8

from webapi.alienvault import scanipv4
from webapi.abuseipdb import ipcheck
from webapi.threatbook import scanip
from webapi.fetchloc import fetchloc1, fetchloc2
from webapi.ifrobot import ifrobot

'''
vulinfo = {'ip': [{'description': description, 'dns': dns}, ...],
            ...
           }
'''
vulinfo = {}
list  = []
def getvulinfo(iplist):
    for key in iplist:
        for x in iplist[key]:
            list.append(scanipv4(key))
            list.append(scanip(key))
            list.append(ipcheck(key))
            vulinfo[key] = list
            list = []


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
    types = []
    for key in iplist:
        for attack_type in iplist[key]:
            types.append(attack_type)
            #list.append(iplist[key][1]) #ins ip 
        for y in scanipv4(key):
            descriptions.append(y['info'])
            dns.append(y['dns'])
        for y in scanip(key):
            descriptions.append(y['info'])
            dns.append(y['dns'])
        for y in ipcheck(key):
            descriptions.append(y['info'])
            dns.append(y['dns'])
        list.append(types)
        list.append(descriptions)
        list.append(dns)
        vulinfo[key] = list
       # print vulinfo[key]
        list = []
    print vulinfo
    return vulinfo

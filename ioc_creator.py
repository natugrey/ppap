#coding=utf-8

import os
import fileinput
import uuid
from datetime import datetime
'''
snort_rules = {'': '',
               '': ''
               }
'''
snort_rules = {'SNMP request tcp': 'snort_rule_for_SNMP_REQUEST_TCP',
               'SCAN FIN': 'snort_rule_for_SCAN_FIN'
                }

def printIOCHeader(description,f):
    f.write('<?xml version="1.0" encoding="us-ascii"?>\n')
    f.write(
        '<ioc xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" id="' + f.name.rstrip(
            ".ioc") + '" last-modified="' + datetime.now().replace(
            microsecond=0).isoformat() + '" xmlns="http://schemas.mandiant.com/2010/ioc">\n')
    f.write('\t<short_description> ip threat </short_description>\n')
    f.write('\t<description> %s </description>\n'%description)
    f.write('\t<authored_by> wangxin 17 </authored_by>\n')
    f.write('\t<authored_date>' + datetime.now().replace(microsecond=0).isoformat() + '</authored_date>\n')
    f.write('\t<links />\n')
    f.write('\t<definition>\n')
    f.write('\t\t<Indicator operator="OR" id="' + str(uuid.uuid4()) + '">\n')


def printIOCFooter(f):
    f.write('\t\t</Indicator>\n')
    f.write('\t</definition>\n')
    f.write('</ioc>\n')


def sha256TermPopulate(line, f):
    f.write('\t\t\t<IndicatorItem id="' + str(
        uuid.uuid4()) + '" condition="is">\n\t\t\t\t<Context document="FileItem" search="FileItem/Sha256sum" type="mir" />\n\t\t\t\t<Content type="string">' + line.rstrip() + '</Content>\n\t\t\t</IndicatorItem>\n')


def sha1TermPopulate(line, f):
    f.write('\t\t\t<IndicatorItem id="' + str(
        uuid.uuid4()) + '" condition="is">\n\t\t\t\t<Context document="FileItem" search="FileItem/Sha1sum" type="mir" />\n\t\t\t\t<Content type="string">' + line.rstrip() + '</Content>\n\t\t\t</IndicatorItem>\n')


def md5TermPopulate(line, f):
    f.write('\t\t\t<IndicatorItem id="' + str(
        uuid.uuid4()) + '" condition="is">\n\t\t\t\t<Context document="FileItem" search="FileItem/Md5sum" type="mir" />\n\t\t\t\t<Content type="md5">' + line.rstrip() + '</Content>\n\t\t\t</IndicatorItem>\n')


def domainTermPopulate(domain, f):
    f.write('\t\t\t<IndicatorItem id="' + str(
        uuid.uuid4()) + '" condition="contains">\n\t\t\t\t<Context document="Network" search="Network/DNS" type="mir" />\n\t\t\t\t<Content type="string">' + domain + '</Content>\n\t\t\t</IndicatorItem>\n')

def ipTermPopulate(ip, f):
    f.write('\t\t\t<IndicatorItem id="' + str(
        uuid.uuid4()) + '" condition="is">\n\t\t\t\t<Context document="PortItem" search="PortItem/remoteIP" type="mir" />\n\t\t\t\t<Content type="IP">' + ip + '</Content>\n\t\t\t</IndicatorItem>\n')

def emailTermPopulate(email ,f):
    f.write('\t\t\t<IndicatorItem id="'+str(uuid.uuid4())+'" condition="contains">\n\t\t\t\t<Context document="Email" search="Email/From" type="mir" />\n\t\t\t\t<Content type="string">'+ email + '</Content>\n\t\t\t\t</IndicatorItem>\n')

def snortTermPopulate(snort_rule,f):
    f.write('\t\t\t<IndicatorItem id="'+str(uuid.uuid4())+'" condition="contains">\n\t\t\t\t<Context document="Snort" search="Snort/Snort" type="mir" />\n\t\t\t\t<Content type="string">'+ snort_rule + '</Content>\n\t\t\t\t</IndicatorItem>\n')

def generateIOC(vulinfo):
    iocname = str(uuid.uuid4())
    for key in vulinfo:
        for x in vulinfo[key][0]:
            f = open(iocname + '/iocfiles/%s' % iocname, 'w')
            description = ''
            for y in vulinfo[key][1]:
                description += y
            printIOCHeader(description,f)
            if snort_rules.has_key(x):
                snortTermPopulate(snort_rules[x],f)
            ipTermPopulate(key, f)
            for z in vulinfo[key][2]:
                domainTermPopulate(z, f)
        printIOCFooter(f)
        f.close()


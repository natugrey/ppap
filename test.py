#coding=utf-8
from webapi.alienvault import scanipv4
from webapi.abuseipdb import ipcheck
from webapi.threatbook import scanip
from webapi.fetchloc import fetchloc1, fetchloc2
from webapi.ifrobot import ifrobot
print scanip('104.154.156.120')
print "-------------------\n"
print scanipv4('104.154.156.120')
print "-------------------\n"
print ipcheck('104.154.156.120')
print "-------------------\n"
print fetchloc1('104.154.156.120')
print "-------------------\n"
print fetchloc2('104.154.156.120')
print "-------------------\n"
print ifrobot('104.154.156.120')


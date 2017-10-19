#coding=utf-8
from webapi.alienvault import scanipv4
from webapi.abuseipdb import ipcheck
from webapi.threatbook import scanip
from webapi.fetchloc import fetchloc1, fetchloc2
from webapi.ifrobot import ifrobot

print scanip('88.211.129.250')
print scanipv4('88.211.129.250')
print ipcheck('88.211.129.250')
print fetchloc1('88.211.129.250')
print fetchloc2('88.211.129.250')
print ifrobot('88.211.129.250')


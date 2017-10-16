#coding=utf-8
from webapi.alienvault import scanipv4
from webapi.abuseipdb import ipcheck, ipreport
from webapi.threatbook import scanip
from webapi.fetchloc import fetchloc1, fetchloc2
from webapi.ifrobot import ifrobot

scanip('88.211.129.250')
scanipv4('88.211.129.250')
ipcheck('88.211.129.250')
ipreport('88.211.129.250')
fetchloc1('88.211.129.250')
fetchloc2('88.211.129.250')
ifrobot('88.211.129.250')


#coding=utf-8
import re
import time
from ifapt import ifapt
from vulinfo import getvulinfo

'''
iplist = {'ip':(timestamp,type),
          ...
          }
'''
iplist = {}

# def date2timestamp(date):
#     date = '2017/' + date
#     msec = float(re.match('.*\.([\d]+)', date).group(1))/1000000
#     ndate = re.match('(.*)\.[\d]+', date).group(1)
#     timearray = time.strptime(ndate, '%Y/%m/%d-%H:%M:%S')
#     timestamp = float(time.mktime(timearray))
#     timestamp += msec
#     print("%5f"%(timestamp))
#     return timestamp

#dealing with snort_logs
def dealwithlogs(f):
    while 1:
        line = f.readline()
        if line:
            try:
                ip = re.match('.*\D([\d]+\.[\d]+\.[\d]+\.[\d]+)(:[\d])* ->', line).group(1)
                print ip
                if ip:
                    # date = re.match('([\d]+/[\d]+-[\d]+:[\d]+:[\d]+\.[\d]+)[\D]', line).group(1)
                    type = re.match('.*\[\*\*] \[[^\]]+] ([\w ]+) \[\*\*.*', line).group(1)
                    # timestamp = date2timestamp(date)
                    if not iplist.has_key(ip):
                        iplist[ip] = []
                    # rel = (timestamp,type)
                    iplist[ip].append(type)
            except Exception,e:
                print e
        else:
            break
from ioc_creator import generateIOC
def main():
    # f = open('snort_logs/Scan_alert', 'r');
    # dealwithlogs(f)
    # f.close()
    f = open('snort_logs/ICMP_Redir_alert', 'r')
    dealwithlogs(f)
    f.close()
    print iplist
    # ifapt(iplist)
    vulinfo = getvulinfo(iplist)
    generateIOC(vulinfo)

if __name__ == '__main__':
    main()
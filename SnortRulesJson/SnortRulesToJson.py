# coding:utf-8
#!/usr/bin/python

import json
import re
import os

str_reg = 'msg:[" "]?"(.+?)";'


data=dict()
def create_json(rules_path):
    f_json=open("./dictionary.json","w")
    files= os.listdir(rules_path) #得到文件夹下的所有文件名称 
    print files
    for file in files: #遍历文件夹  
        if not os.path.isdir(file): #判断是否是文件夹，不是文件夹才打开   
            print file  
            f_rule=open(rules_path+"/"+file,"r")
            for rule in f_rule:
                if rule[0]=='#' or rule=='\n':
                    continue
                attack_type = re.findall(str_reg,rule)
                print attack_type[0]
                data[attack_type[0]]=rule
    f_json.write(json.dumps(data,sort_keys=True, indent=4));
    f_rule.close()
    f_json.close()


def getRule(attack_type):
    f_json=open("./dictionary.json","r")
    dic=json.load(f_json)
    #print attack_type
    rule = dic[attack_type]
    f_json.close
    return rule

if __name__ == "__main__":
    rules_path = "/etc/snort/rules" #rule文件夹目录
    #create_json(rules_path)
    attack_type="BACKDOOR DeepThroat 3.1 Server Response [3150]"
    print getRule(attack_type)



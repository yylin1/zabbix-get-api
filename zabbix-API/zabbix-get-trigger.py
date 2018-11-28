#!/usr/bin/env python
#coding:utf-8
import json
import urllib2
from urllib2 import URLError
import sys
import time
zabbix_addresses=['http://10.111.200.8/zabbix/api_jsonrpc.php,admin,zabbix']
class ZabbixTools:
    def __init__(self,address,username,password):

        self.address = address
        self.username = username
        self.password = password

        self.url = '%s/api_jsonrpc.php' % self.address
        self.header = {"Content-Type":"application/json"}



    def user_login(self):
        data = json.dumps({
                           "jsonrpc": "2.0",
                           "method": "user.login",
                           "params": {
                                      "user": self.username,
                                      "password": self.password
                                      },
                           "id": 0
                           })

        request = urllib2.Request(self.url, data)
        for key in self.header:
            request.add_header(key, self.header[key])

        try:
            result = urllib2.urlopen(request)
        except URLError as e:
            print "Auth Failed, please Check your name and password:", e.code
        else:
            response = json.loads(result.read())
            result.close()
            #print response['result']
            print('\n')
            self.authID = response['result']
            return self.authID

    def trigger_get(self):
        data = json.dumps({
                           "jsonrpc":"2.0",
                           "method":"trigger.get",
                           "params": {
                                      "output": [
                                                "triggerid",
                                                "description",
                                                "status",
                                                "priority"
                                                ],
                                      "filter": {
                                                 "value": 1
                                                 },
                                      "sortfield": "priority",
                                      "sortorder": "DESC",
                                      "min_severity": 4,
                                      "skipDependent": 1,
                                      "monitored": 1,
                                      "active": 1,
                                      "expandDescription": 1,
                                      "selectHosts": ['host'],
                                      "selectGroups": ['name'],
                                      "only_true": 1
                                    },
                           "auth": self.user_login(),
                           "id":1
        })

        request = urllib2.Request(self.url, data)
        for key in self.header:
            request.add_header(key, self.header[key])

        try:
            result = urllib2.urlopen(request)
        except URLError as e:
            print "Error as ", e
        else:
            response = json.loads(result.read())
            #print (response, "\n")
            result.close()
            issues = response['result']
            content = ''
            if issues:
                #print (issues)
                #print (len(issues))
                for line in issues:
                    #content = content + "%s:%s:%s:%s\n---------------\n" % (line['groups'],line['hosts'],line['description'],str(line['status']))
                    print ("Trigger message list:  [ %s ] view :status %s" % (line['description'],line['status']))
#                    print ('line print ',line)
            else:
                print ("No Trigger load high problem in list.")
            return content

if __name__ == "__main__":
    for zabbix_addres in zabbix_addresses:
        address,username,password = zabbix_addres.split(',')
        z = ZabbixTools(address=address, username=username, password=password)
        content = z.trigger_get()
        print (content)
    #print    content



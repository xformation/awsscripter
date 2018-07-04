#!/usr/bin/env python
# Working csv report upload to ES
import datetime
import csv
import time
import urllib
import json
import os
import sys
import urllib.request
from urllib.request import Request, urlopen  # Python 3
from awsscripter.common.LambdaBase import LambdaBase


class Billtoes():
    # Enable Elasticsearch Security
    # read_username and read_password for read ES cluster information
    # write_username and write_passowrd for write monitor metric to ES.
    read_es_security_enable = False
    read_username = "read_username"
    read_password = "read_password"

    write_es_security_enable = False
    write_username = "write_username"
    write_password = "write_password"

    # elasticServer = ""
    # interval = ""
    # elasticIndex = ""
    # elasticMonitoringCluster = ""

    def __init__(self,path,esurl,index,read_es_security_enable = False,write_es_security_enable = False):
        self.read_es_security_enable=False
        self.write_es_security_enable=False
        self.path=path
        self.esurl=esurl
        self.index=index
        self.elasticServer = os.environ.get('ES_CPU_CLUSTER_URL', esurl)
        self.elasticIndex = os.environ.get('ES_METRICS_INDEX_NAME', index)
        self.elasticMonitoringCluster = os.environ.get('ES_METRICS_CPUMONITORING_CLUSTER_URL', esurl)

    # urlvar = 'http://10.10.10.50:4571'
    # elasticServer = os.environ.get('ES_CPU_CLUSTER_URL', urlvar)
    # interval = int(os.environ.get('ES_CPU_INTERVAL', '60'))
    #
    # # ElasticSearch Cluster to Send Metrics
    # elasticIndex = os.environ.get('ES_METRICS_INDEX_NAME', 'scripter_report')
    # elasticMonitoringCluster = os.environ.get('ES_METRICS_CPUMONITORING_CLUSTER_URL', 'http://10.10.10.50:4571')


    def handle_urlopen(self,urlData, username, password):
        if self.read_es_security_enable:
            password_mgr = urllib.HTTPPasswordMgrWithDefaultRealm()
            password_mgr.add_password(None, urlData, username, password)
            handler = urllib.HTTPBasicAuthHandler(password_mgr)
            opener = urllib.build_opener(handler)
            urllib.install_opener(opener)
            response = urllib.request.urlopen(urlData)
        else:
            response = urllib.request.urlopen(urlData)
        return response.read().decode('utf-8')

    def myconverter(self,value):
        try:
            value=float(value)
            return value
        except ValueError:
            return value


    def fetch_clusterhealth(self):
        try:
            jsonData = {}
            utc_datetime = datetime.datetime.utcnow()
            endpoint = "/_cluster/health"
            urlData = self.elasticServer #+ endpoint
            print(urlData)
            response = self.handle_urlopen(urlData,username=None, password=None)
            # with open("D:\\Hourlybilling_report-1.csv") as csvfile:
            with open(self.path) as csvfile:
                reader = csv.DictReader(csvfile)
                title = reader.fieldnames
                for row in reader:
                    for key, val in row.items():
                        jsonData[key] = self.myconverter(val)
                    # print(jsonData)
                    self.post_data(jsonData, username=None, password=None)
            clusterName = 'elasticsearch'
            return clusterName
        except IOError as err:
            print ("IOError: Maybe can't connect to elasticsearch.")
            clusterName = "unknown"
            return clusterName


    def post_data(self,data,username,password):
        utc_datetime = datetime.datetime.utcnow()
        url_parameters = {'cluster': self.elasticMonitoringCluster, 'index': self.elasticIndex,
            'index_period': utc_datetime.strftime("%Y.%m.%d"), }
        url = "%(cluster)s/%(index)s-%(index_period)s/cpudata" % url_parameters
        print(url)
        headers = {'content-type': 'application/json'}
        try:
            req = Request(url)
            req.add_header('Content-Type', 'application/json; charset=utf-8')
            jsondata = json.dumps(data)
            jsondataasbytes = jsondata.encode('utf-8')

            req.add_header('Content-Length', len(jsondataasbytes))
            data =  urllib.parse.urlencode(data).encode("utf-8")
            # req = urllib.request.urlopen(url, headers=headers, data=json.dumps(data))
            if self.write_es_security_enable:
                password_mgr = urllib.HTTPPasswordMgrWithDefaultRealm()
                password_mgr.add_password(None, url, username, password)
                handler = urllib.HTTPBasicAuthHandler(password_mgr)
                opener = urllib.build_opener(handler)
                urllib.install_opener(opener)
                response = urllib.request.urlopen(req, jsondataasbytes)
            else:
                response = urllib.request.urlopen(req, jsondataasbytes)
        except Exception as e:
            print ("Error:  {}".format(str(e)))

    def starter(self):
        # urlvar = 'http://10.10.10.50:4571'
        print(self.esurl)
        elasticServer = os.environ.get('ES_CPU_CLUSTER_URL', self.esurl)
        print(elasticServer)
        interval = int(os.environ.get('ES_CPU_INTERVAL', '60'))

        # ElasticSearch Cluster to Send Metrics
        elasticIndex = os.environ.get('ES_METRICS_INDEX_NAME', self.index)
        elasticMonitoringCluster = os.environ.get('ES_METRICS_CPUMONITORING_CLUSTER_URL', 'http://10.10.10.50:4571')
        clusterName = self.fetch_clusterhealth()
# if __name__ == '__main__':
#     path="D:\\Hourlybilling_report-1.csv"
#     esurl='http://10.10.10.50:4571'
#     biller = Billtoes(path, esurl)
#     biller.starter()
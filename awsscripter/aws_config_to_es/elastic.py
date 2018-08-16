import datetime
import json
import logging
import urllib

import requests
# from aws_config_to_es.esingest import destination
from urllib.request import Request, urlopen  # Python 3
class ElasticSearch(object):

    def __init__(self, connections=None, log=None):

        if connections is None:
            self.connections = "localhost:9200"
        else:
            self.connections = connections

        if log is not None:
            self.log = log
        else:
            self.log = logging.getLogger("elastic")

        self.log.debug("Setting up the initial connection")

    def add(
            self, index_name=None, doc_type=None, index_id=None,
            json_message=None):
        """
            Returns the id of the newly inserted value or None
            if the added date is not there, then I'm adding it in
        """
        if not isinstance(json_message, dict):
            json_message_dict = json.loads(json_message)
        else:
            json_message_dict = json_message
        # print(self.connections)
        json_message_dict["addedIso"] = datetime.datetime.now().isoformat()
        json_message_dict["updatedIso"] = json_message_dict["addedIso"]
        # destination = 'http:localhost:9200'
        url_parameters = {'cluster': self.connections, 'index': index_name, 'doctype': doc_type}
        url = "%(cluster)s/%(index)s/%(doctype)s" % url_parameters
        headers = {'content-type': 'application/json'}

        req = Request(url)
        req.add_header('Content-Type', 'application/json; charset=utf-8')

        json_message = json.dumps(json_message_dict)

        jsondataasbytes = json_message.encode('utf-8')

        self.log.info("adding item into ES: " + str(json_message_dict))

        if index_id:
            # response = requests.put(self.connections + "/" +
            #                         index_name + "/" +
            #                         doc_type + "/" +
            #                         index_id, data=jsondataasbytes)
            response = urllib.request.urlopen(req, jsondataasbytes)
            print("puttoes" + response)
        else:
            # response = requests.post(self.connections + "/" +
            #                          index_name + "/" +
            #                          doc_type, data=jsondataasbytes)
            response = urllib.request.urlopen(req, jsondataasbytes)
            # print("puttoes"+response)
        # self.log.info(
        #     "response: " + str(
        #         response.content) + "...message: " + str(
        #         response.content))
        self.log.info(
            "response: " + str(
                response) + "...message: " + str(
                response))

        responseid = None
        if response:
            responseid = 'added'
        else:
            responseid = None
        # try:
        #     responseid = json.loads(response.content).get("_id")
        # except Exception:
        #     pass

        return responseid

    def set_not_analyzed_template(self):
        """
        Sets the indexName and typeName as not_analyzed, which means that
        the data won't be tokenized, and therefore can be
        searched by the value itself
        """

        payload = {
            "template": "*",
            "settings": {
                "index.refresh_interval": "5s"
            },
            "mappings": {
                "_default_": {
                    "_all": {"enabled": True},
                    "dynamic_templates": [{
                        "string_fields": {
                            "match": "*",
                            "match_mapping_type": "text",
                            "mapping": {
                                "type": "text",
                                "index": "analyzed",
                                "omit_norms": True,
                                "fields": {
                                    "raw": {"type": "text",
                                            "index": "not_analyzed",
                                            "ignore_above": 256}
                                }
                            }
                        }
                    }]
                }
            }
        }
        requests.put(
            self.connections + "/_template/configservice",
            data=json.dumps(payload))

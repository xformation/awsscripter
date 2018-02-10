import logging

import json
import csv
import time
import sys
import re
import tempfile
import getopt
import os
from datetime import datetime
import boto3
from dateutil.tz import tzutc
from awsscripter.audit.audit import Audit
from awsscripter.audit.audit_status import AuditStatus
from awsscripter.common.AwsBase import AwsBase
from awsscripter.common.connection_manager import ConnectionManager
from awsscripter.common.exceptions import UnknownAuditStatusError

class cloud_trails():

    def get_regions(self):
        """Summary

        Returns:
            TYPE: Description
        """
        client = boto3.client('ec2')
        region_response = client.describe_regions()
        regions = [region['RegionName'] for region in region_response['Regions']]
        return regions


    def get_cloudtrails(self, regions):
        """Summary

        Returns:
            TYPE: Description
        """
        trails = dict()
        for n in regions:
            client = boto3.client('cloudtrail', region_name=n)
            response = client.describe_trails()
            temp = []
            for m in response['trailList']:
                if m['IsMultiRegionTrail'] is True:
                    if m['HomeRegion'] == n:
                        temp.append(m)
                else:
                    temp.append(m)
            if len(temp) > 0:
                trails[n] = temp
        return trails


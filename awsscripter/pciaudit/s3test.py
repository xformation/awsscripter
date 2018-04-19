from __future__ import print_function

import json

from awsscripter.common.connection_manager import ConnectionManager
import time
import sys
import yaml

from datetime import datetime
import boto3

class Control():
    # --- Script controls ---

    # CIS Benchmark version referenced. Only used in web report.
    AWS_CIS_BENCHMARK_VERSION = "1.1"

    # Would you like a HTML file generated with the result?
    # This file will be delivered using a signed URL.
    S3_WEB_REPORT = True

    # Where should the report be delivered to?
    # Make sure to update permissions for the Lambda role if you change bucket name.
    S3_WEB_REPORT_BUCKET = "CHANGE_ME_TO_YOUR_S3_BUCKET"

    # Create separate report files?
    # This will add date and account number as prefix. Example: cis_report_111111111111_161220_1213.html
    S3_WEB_REPORT_NAME_DETAILS = True

    # How many hours should the report be available? Default = 168h/7days
    S3_WEB_REPORT_EXPIRE = "168"

    # Set to true if you wish to anonymize the account number in the report.
    # This is mostly used for demo/sharing purposes.
    S3_WEB_REPORT_OBFUSCATE_ACCOUNT = False

    # Would  you like to send the report signedURL to an SNS topic
    SEND_REPORT_URL_TO_SNS = False
    SNS_TOPIC_ARN = "CHANGE_ME_TO_YOUR_TOPIC_ARN"

    # Would you like to print the results as JSON to output?
    SCRIPT_OUTPUT_JSON = True

    # Would you like to supress all output except JSON result?
    # Can be used when you want to pipe result to another system.
    # If using S3 reporting, please enable SNS integration to get S3 signed URL
    OUTPUT_ONLY_JSON = False

    # Control 1.1 - Days allowed since use of root account.
    CONTROL_1_1_DAYS = 0

    """def __init__(self,parameter=None):
        self.connection_manager = ConnectionManager(region="us-east-1")
        self.parameter = "list_virtual_mfa_devices
    """""
    def __init__(
            self, region="us-east-1", iam_role=None,
            parameters=None, awsscripter_user_data=None, hooks=None, s3_details=None,
            dependencies=None, role_arn=None, protected=False, tags=None,
            notifications=None, on_failure=None
    ):
        #self.logger = logging.getLogger(__name__)
        self.connection_manager = ConnectionManager(region, iam_role)
        self.hooks = hooks or {}
        self.parameters = parameters or {}
        self.awsscripter_user_data = awsscripter_user_data or {}
        self.notifications = notifications or []
        self.s3_details = s3_details
        self.protected = protected
        self.role_arn = role_arn
        self.on_failure = on_failure
        self.dependencies = dependencies or []
        self.tags = tags or {}


    # def _format_parameters(self, parameters):
    #     """
    #     Converts CloudFormation parameters to the format used by Boto3.
    #
    #     :param parameters: A dictionary of parameters.
    #     :type parameters: dict
    #     :returns: A list of the formatted parameters.
    #     :rtype: list
    #     """
    #     formatted_parameters = []
    #     for name, value in parameters.items():
    #         if value is None:
    #             continue
    #         if isinstance(value, list):
    #             value = ",".join(value)
    #         formatted_parameters.append({
    #             "ParameterKey": name,
    #             "ParameterValue": value
    #         })
    #
    #     return formatted_parameters
# | 4.2 | s3_bucket_public_read_prohibited
    def DP_4_2_s3_bucket_public_read_prohibited(self):
        result = True
        failReason = ""
        offenders = []
        control = "4.2"
        description = "No Public read access for S3 Buckets"
        scored = False
        offenders = []
        s3_client = boto3.client('s3')
        buckets = s3_client.list_buckets()
        public_access = False
        for bucket in buckets['Buckets']:
            # print(bucket)
            acl_bucket = s3_client.get_bucket_acl(Bucket=bucket['Name'])
            # print(yaml.dump(acl_bucket))
            for grantee in acl_bucket['Grants']:
                # print(grantee['Grantee'])
                # print(grantee['Permission'])
                if (grantee['Permission']) == 'READ':
                    # print(grantee['Grantee'])
                    for uri in (grantee['Grantee'].keys()):
                        if uri == 'URI':
                            if ((grantee['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers')):# && (grantee['Permission'] == 'Read')):# and grantee['Grantee']['Permission'] == 'FULL_CONTROL':
                                public_access = True
                                print(public_access)
            if public_access == True:
                offenders.append(bucket['Name'])
                public_access = False
        if len(offenders) > 0:
            result = False
            failReason = "There S3 Buckets available with Public Read Access"
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}
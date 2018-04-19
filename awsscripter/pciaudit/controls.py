from __future__ import print_function
from awsscripter.common.connection_manager import ConnectionManager
import time
import sys
import re

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
        # self.logger = logging.getLogger(__name__)
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

    def _format_parameters(self, parameters):
        """
        Converts CloudFormation parameters to the format used by Boto3.

        :param parameters: A dictionary of parameters.
        :type parameters: dict
        :returns: A list of the formatted parameters.
        :rtype: list
        """
        formatted_parameters = []
        for name, value in parameters.items():
            if value is None:
                continue
            if isinstance(value, list):
                value = ",".join(value)
            formatted_parameters.append({
                "ParameterKey": name,
                "ParameterValue": value
            })

        return formatted_parameters

    def LM_2_1_cloudtrail_centralized_encrypted_lfi(self):
        # This rule verifies that a defined CloudTrail Trail send all logs to centralized S3 bucket.
        #
        # Scope
        # This rule covers one particular trail and is triggered periodically.
        #
        # Prerequisites
        # Configure the following parameters in the Config Rules configuration:
        # 1) RoleToAssume [present by default]
        # Configure the following in the code of this lambda function
        # 2) AWS_CLOUDTRAIL_NAME [Name of the Trail to look for]
        # 3) AWS_CLOUDTRAIL_S3_BUCKET_NAME [Name of the S3 bucket, ideally in the centralized Security Logging Account]
        # 4) AWS_CLOUDTRAIL_KMS_KEY_ARN [KMS CMK ARN used to encrypt CloudTrail, ideally in the centralized Security Logging Account]
        #
        # Use cases
        # The following logic is applied:
        # No Trail is configured -> NOT COMPLIANT
        # No Trail named AWS_CLOUDTRAIL_NAME value is configured -> NOT COMPLIANT
        # The Trail named AWS_CLOUDTRAIL_NAME value is inactive -> NOT COMPLIANT
        # The Trail named AWS_CLOUDTRAIL_NAME value is not including global resources -> NOT COMPLIANT
        # The Trail named AWS_CLOUDTRAIL_NAME value is not multi-region -> NOT COMPLIANT
        # The Trail named AWS_CLOUDTRAIL_NAME value has no Log File Integrity -> NOT COMPLIANT
        # The Trail named AWS_CLOUDTRAIL_NAME value is not logging all Management Events -> NOT COMPLIANT
        # The Trail named AWS_CLOUDTRAIL_NAME value is not logging all S3 Data Events -> NOT COMPLIANT
        # AWS_CLOUDTRAIL_S3_BUCKET_NAME is not defined -> NOT COMPLIANT
        # The Trail named AWS_CLOUDTRAIL_NAME value is not logging in AWS_CLOUDTRAIL_S3_BUCKET_NAME -> NOT COMPLIANT
        # AWS_CLOUDTRAIL_KMS_KEY_ARN is not defined -> NOT COMPLIANT
        # The Trail named AWS_CLOUDTRAIL_NAME value is not encrypted -> NOT COMPLIANT
        # The Trail named AWS_CLOUDTRAIL_NAME value is not encrypted using AWS_CLOUDTRAIL_KMS_KEY_ARN -> NOT COMPLIANT
        # The Trail named AWS_CLOUDTRAIL_NAME value is active, global, log file integrity, logging in AWS_CLOUDTRAIL_S3_BUCKET_NAME and encrypted with AWS_CLOUDTRAIL_KMS_KEY_ARN -> COMPLIANT
        """Summary

               Returns:
                   TYPE: Description
               """
        result = True
        failReason = ""
        offenders = []
        control = "2.1"
        description = "Cloud Trail lfi"
        scored = False

        cloudtrail_client = boto3.client("cloudtrail")

        AWS_CLOUDTRAIL_NAME = ' '
        eval = {}
        eval["Configuration"] = cloudtrail_client.describe_trails()['trailList']
        print(eval)

        if len(eval['Configuration']) == 0:
            result = False
            Failreason = "No configuration Found"

            for trail in eval['Configuration']:
                AWS_CLOUDTRAIL_NAME = trail['Name']
                correct_trail = trail
                correct_trail_status = cloudtrail_client.get_trail_status(Name=AWS_CLOUDTRAIL_NAME)
                correct_trail = cloudtrail_client.describe_trails(trailNameList=[AWS_CLOUDTRAIL_NAME])['trailList'][0]
                correct_trail_selector = \
                    cloudtrail_client.get_event_selectors(TrailName=AWS_CLOUDTRAIL_NAME)['EventSelectors'][0]
                print(correct_trail)
                print(correct_trail_status)
                print(correct_trail_selector)
                if correct_trail_status['IsLogging'] != True:
                    result = False
                    failReason = "The Trail named " + correct_trail + " is not enabled."

                #     else:
                elif correct_trail['IncludeGlobalServiceEvents'] != True:
                    result = "False",
                    failReason = "The Trail named " + AWS_CLOUDTRAIL_NAME + " is not logging global resources."

                elif correct_trail['IsMultiRegionTrail'] != True:
                    result = False,
                    failReason = "The Trail named " + AWS_CLOUDTRAIL_NAME + " is not logging in all regions."

                elif correct_trail['LogFileValidationEnabled'] != True:
                    result = False
                    Failreason = "The Trail named " + AWS_CLOUDTRAIL_NAME + " has not log file integrity enabled."
                elif correct_trail_selector['ReadWriteType'] != 'All' or correct_trail_selector[
                    'IncludeManagementEvents'] != True:
                    result = False
                    Failreason = "The Trail named " + AWS_CLOUDTRAIL_NAME + " do not log ALL Management events."


                elif True:
                    if len(correct_trail_selector['DataResources'])==0:
                        print("DataResources are empty")
                        result = False
                        Failreason = "Not Comopliant" + AWS_CLOUDTRAIL_NAME + "the value is zero."
                    else:
                        if correct_trail_selector['DataResources'][0] != "{'Type': 'AWS::S3::Object', 'Values': ['arn:aws:s3']}":
                            result = False
                            failReason = "the trail name" + AWS_CLOUDTRAIL_NAME + "do not log all S3 Data Events."


                elif correct_trail['S3BucketName'] != True:
                    result = "NON_COMPLIANT"
                    failreason = "The Trail named " + correct_trail + " is not logging in the S3 bucket named " +AWS_CLOUDTRAIL_S3_BUCKET_NAME + "."

        # elif AWS_CLOUDTRAIL_KMS_KEY_ARN == "":
        #     result = "NON_COMPLIANT"
        #     failreason = "The parameter \"AWS_CLOUDTRAIL_KMS_KEY_ARN\" is not defined in the lambda code. Contact the Security team."
        # elif 'KmsKeyId' not in new_trail_name:
        #     result = "NON_COMPLIANT",
        #     failReason = "The Trail named " + AWS_CLOUDTRAIL_NAME + " is not encrypted."


        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

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
    # --- 1 Identity and Access Management ---

    # 1.1 Avoid the use of the "root" account (Scored)
    def control_1_1_root_use(self, credreport):
        """Summary

        Args:
            credreport (TYPE): Description

        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "1.1"
        description = "Avoid the use of the root account"
        scored = True
        if "Fail" in credreport:  # Report failure in control
            sys.exit(credreport)
        # Check if root is used in the last 24h
        now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
        frm = "%Y-%m-%dT%H:%M:%S+00:00"

        try:
            pwdDelta = (datetime.strptime(now, frm) - datetime.strptime(credreport[0]['password_last_used'], frm))
            if (pwdDelta.days == self.CONTROL_1_1_DAYS) & (pwdDelta.seconds > 0):  # Used within last 24h
                failReason = "Used within 24h"
                result = False
        except:
            if credreport[0]['password_last_used'] == "N/A" or "no_information":
                pass
            else:
                print("Something went wrong")

        try:
            key1Delta = (
            datetime.strptime(now, frm) - datetime.strptime(credreport[0]['access_key_1_last_used_date'], frm))
            if (key1Delta.days == self.CONTROL_1_1_DAYS) & (key1Delta.seconds > 0):  # Used within last 24h
                failReason = "Used within 24h"
                result = False
        except:
            if credreport[0]['access_key_1_last_used_date'] == "N/A" or "no_information":
                pass
            else:
                print("Something went wrong")
        try:
            key2Delta = datetime.strptime(now, frm) - datetime.strptime(credreport[0]['access_key_2_last_used_date'],
                                                                        frm)
            if (key2Delta.days == self.CONTROL_1_1_DAYS) & (key2Delta.seconds > 0):  # Used within last 24h
                failReason = "Used within 24h"
                result = False
        except:
            if credreport[0]['access_key_2_last_used_date'] == "N/A" or "no_information":
                pass
            else:
                print("Something went wrong")
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}
    def control_1_2_root_mfa_enabled(self):

        """Summary

        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "1.2"
        description = "Ensure MFA is enabled for the root account"
        scored = True
        response = self.connection_manager.call(
            service='iam',
            command='get_account_summary',
            kwargs=None
        )#Audit.IAM_CLIENT.get_account_summary()
        if response['SummaryMap']['AccountMFAEnabled'] != 1:
            result = False
            failReason = "Root account not using MFA"
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    def control_1_3_no_active_root_accesskey_used(self, credreport):
        """Summary

        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "1.3"
        description = "No Root access key should be used"
        scored = False
        offenders = []
        for n, _ in enumerate(credreport):
            if (credreport[n]['access_key_1_active'] or credreport[n]['access_key_2_active'] == 'true'):
                result= False
            else:
                offenders="root"
                failReason="Root Access Key in use"
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    def control_1_4_iam_policy_no_full_star(self):
        result = True
        failReason = ""
        offenders = []
        control = "1.4"
        description = "No Full star to be used"
        scored = False
        offenders = []

        iam = boto3.client("iam")
        response = iam.list_policies(Scope='Local')

        for configuration_item in response["Policies"]:
            policy_info = iam.get_policy(PolicyArn=configuration_item["Arn"])
            print(policy_info)
            print("=====================")
            if policy_info["Policy"]["IsAttachable"] == False:
                status = "NOT_APPLICABLE"
            else:
                policy_version = iam.get_policy_version(PolicyArn=configuration_item["Arn"],
                                                        VersionId=policy_info['Policy']['DefaultVersionId'])
                print("policy version +++++++++++++",policy_version)
                for statement in policy_version['PolicyVersion']['Document']['Statement']:
                    print(statement)
                    star_statement = False
                    if type(statement['Action']) is list:
                        for action in statement['Action']:
                            if action == "*":
                                star_statement = True
                    else:  # just one Action
                        if statement['Action'] == "*":
                            star_statement = True

                    star_resource = False
                    if type(statement['Resource']) is list:
                        for action in statement['Resource']:
                            if action == "*":
                                star_resource = True
                    else:  # just one Resource
                        if statement['Resource'] == "*":
                            star_resource = True

                    if star_statement and star_resource:
                        status = 'NON_COMPLIANT'
                    else:
                        status = 'COMPLIANT'

            ResourceId = configuration_item["PolicyId"]
            ResourceType = "AWS::IAM::Policy"
            # config = boto3.client("config")
            # config.put_evaluations(
            #     Evaluations=[
            #         {
            #             "ComplianceResourceType": ResourceType,
            #             "ComplianceResourceId": ResourceId,
            #             "ComplianceType": status,
            #             "Annotation": "No full * (aka full permission) in an IAM Policy should be attached to IAM Users/Groups/Roles.",
            #             "OrderingTimestamp": str(datetime.now())
            #         },
            #     ],
            #     ResultToken=result_token
            # )

        # Verify the AWS managed policy named AdminstratorAccess
        admin_response = iam.get_policy(PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
        ResourceType = "AWS::IAM::ManagedPolicy"
        ResourceId = "AdministratorAccess"
        if int(admin_response["Policy"]["AttachmentCount"]) > 0:
            status = "NON_COMPLIANT"
        else:
            status = "COMPLIANT"

        if status == "NON_COMPLIANT":
            failReason="full * (aka full permission) in an IAM Policy"
            result=False
        else:
            failReason=""
            result=True
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,'Description': description, 'ControlId': control}


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
        description = "No Root access key should be used"
        scored = False
        offenders = []
        cloudtrail_client = boto3.client("cloudtrail")

        AWS_CLOUDTRAIL_NAME = 'Security_Trail_DO-NOT-MODIFY'
        eval = {}
        eval["Configuration"] = cloudtrail_client.describe_trails()['trailList']
        print(eval)

        if len(eval['Configuration']) == 0:
            response = {
                "ComplianceType": "NON_COMPLIANT",
                "Annotation": "No Trail is configured.",
                "result": False,
                "Failreason": "No configuration Found"
            }
        else:
            trail_found = False

            for trail in eval['Configuration']:
                if trail["Name"] == AWS_CLOUDTRAIL_NAME:
                    trail_found = True
            if trail_found == False:
                response = {
                    "ComplianceType": "NON_COMPLIANT",
                    "Annotation": "No Trail named " + AWS_CLOUDTRAIL_NAME + " is configured."
                }
            else:
                correct_trail_status = cloudtrail_client.get_trail_status(Name=AWS_CLOUDTRAIL_NAME)
                correct_trail = cloudtrail_client.describe_trails(trailNameList=[AWS_CLOUDTRAIL_NAME])['trailList'][0]
                correct_trail_selector = \
                cloudtrail_client.get_event_selectors(TrailName=AWS_CLOUDTRAIL_NAME)['EventSelectors'][0]

                if correct_trail_status['IsLogging'] != True:
                    response = {
                        "ComplianceType": "NON_COMPLIANT",
                        "Annotation": "The Trail named " + AWS_CLOUDTRAIL_NAME + " is not enabled.",
                        "result": False,
                        "Failreason": "Not Comopliant"
                    }
                if 'LatestDeliveryError' in correct_trail_status:
                    response = {
                        "ComplianceType": "NON_COMPLIANT",
                        "Annotation": "The Trail named " + AWS_CLOUDTRAIL_NAME + " did not delivered the log as expected. The current error is " +
                                      correct_trail_status['LatestDeliveryError'] + ". Contact the Security team.",
                        "result": False,
                        "Failreason": "Not Comopliant"
                    }
                elif correct_trail['IncludeGlobalServiceEvents'] != True:
                    response = {
                        "ComplianceType": "NON_COMPLIANT",
                        "Annotation": "The Trail named " + AWS_CLOUDTRAIL_NAME + " is not logging global resources.",
                        "result": False,
                        "Failreason": "Not Comopliant"
                    }
                elif correct_trail['IsMultiRegionTrail'] != True:
                    response = {
                        "ComplianceType": "NON_COMPLIANT",
                        "Annotation": "The Trail named " + AWS_CLOUDTRAIL_NAME + " is not logging in all regions.",
                        "result": False,
                        "Failreason": "Not Comopliant"
                    }
                elif correct_trail['LogFileValidationEnabled'] != True:
                    response = {
                        "ComplianceType": "NON_COMPLIANT",
                        "Annotation": "The Trail named " + AWS_CLOUDTRAIL_NAME + " has not log file integrity enabled.",
                        "result": False,
                        "Failreason": "Not Comopliant"
                    }
                elif correct_trail_selector['ReadWriteType'] != 'All' or correct_trail_selector[
                    'IncludeManagementEvents'] != True:
                    response = {
                        "ComplianceType": "NON_COMPLIANT",
                        "Annotation": "The Trail named " + AWS_CLOUDTRAIL_NAME + " do not log ALL Management events.",
                        "result": False,
                        "Failreason": "Not Comopliant"
                    }
                elif str(correct_trail_selector['DataResources'][
                             0]) != "{'Type': 'AWS::S3::Object', 'Values': ['arn:aws:s3']}":
                    response = {
                        "ComplianceType": "NON_COMPLIANT",
                        "Annotation": "The Trail named " + AWS_CLOUDTRAIL_NAME + " do not log ALL S3 Data Events.",
                        "result": False,
                        "Failreason": "Not Comopliant"
                    }
                # elif AWS_CLOUDTRAIL_S3_BUCKET_NAME == "":
                #     response = {
                #         "ComplianceType": "NON_COMPLIANT",
                #         "Annotation": "The parameter \"AWS_CLOUDTRAIL_S3_BUCKET_NAME\" is not defined in the lambda code. Contact the Security team."
                #     }
                # elif correct_trail['S3BucketName'] != AWS_CLOUDTRAIL_S3_BUCKET_NAME:
                #     response = {
                #         "ComplianceType": "NON_COMPLIANT",
                #         "Annotation": "The Trail named " + AWS_CLOUDTRAIL_NAME + " is not logging in the S3 bucket named " + AWS_CLOUDTRAIL_S3_BUCKET_NAME + "."
                #     }
                # elif AWS_CLOUDTRAIL_KMS_KEY_ARN == "":
                #     response = {
                #         "ComplianceType": "NON_COMPLIANT",
                #         "Annotation": "The parameter \"AWS_CLOUDTRAIL_KMS_KEY_ARN\" is not defined in the lambda code. Contact the Security team."
                #     }
                # elif 'KmsKeyId' not in correct_trail:
                #     response = {
                #         "ComplianceType": "NON_COMPLIANT",
                #         "Annotation": "The Trail named " + AWS_CLOUDTRAIL_NAME + " is not encrypted."
                #     }
                # elif correct_trail['KmsKeyId'] != AWS_CLOUDTRAIL_KMS_KEY_ARN:
                #     response = {
                #         "ComplianceType": "NON_COMPLIANT",
                #         "Annotation": "The Trail named " + AWS_CLOUDTRAIL_NAME + " is not encrypted using " + AWS_CLOUDTRAIL_KMS_KEY_ARN + "."
                #     }
                else:
                    response = {
                        "ComplianceType": "COMPLIANT",
                        "Annotation": "The Trail named " + AWS_CLOUDTRAIL_NAME + " is active and well defined to send logs to " + AWS_CLOUDTRAIL_S3_BUCKET_NAME + " and proper encryption."
                    }

        # eval["ComplianceResourceType"] = "AWS::CloudTrail::Trail"
        # eval["ComplianceResourceId"] = AWS_CLOUDTRAIL_NAME
        # eval["ComplianceType"] = response["ComplianceType"]
        # eval["Annotation"] = response["Annotation"]
        # eval["OrderingTimestamp"] = json.loads(event["invokingEvent"])['notificationCreationTime']
        # put_eval(eval, result_token)
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

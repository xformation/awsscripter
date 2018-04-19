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
        description = "Cloud Trail lfi"
        scored = False
        offenders = []
        cloudtrail_client = boto3.client("cloudtrail")

        # AWS_CLOUDTRAIL_NAME = 'Security_Trail_DO-NOT-MODIFY'
        eval = {}
        eval["Configuration"] = cloudtrail_client.describe_trails()['trailList']
        print(eval)
        #No Trail is configured -> NOT COMPLIANT
        if len(eval['Configuration']) == 0:
            result = False
            failReason = "No configuration Found"
        for trail in eval['Configuration']:
            AWS_CLOUDTRAIL_NAME = trail['Name']
            correct_trail_name=trail
            correct_trail_status = cloudtrail_client.get_trail_status(Name=AWS_CLOUDTRAIL_NAME)
            correct_trail=cloudtrail_client.describe_trails(trailNameList=[AWS_CLOUDTRAIL_NAME])['trailList'][0]
            correct_trail_selector = \
            cloudtrail_client.get_event_selectors(TrailName=AWS_CLOUDTRAIL_NAME)['EventSelectors'][0]
            print("print Correct_trail")
            print(correct_trail_status)
            print((correct_trail_selector))
            AWS_CLOUDTRAIL_S3_BUCKET_NAME = correct_trail['S3BucketName']
            # The Trail named AWS_CLOUDTRAIL_NAME value is inactive -> NOT COMPLIANT
            if correct_trail_status['IsLogging'] != True:
                result= False
                failReason = "The Trail named "+ AWS_CLOUDTRAIL_NAME +" is not enabled."
            # The Trail named AWS_CLOUDTRAIL_NAME value is not including global resources -> NOT COMPLIANT
            elif correct_trail['IncludeGlobalServiceEvents'] != True:
                result = False
                failReason = "The Trail named "+ AWS_CLOUDTRAIL_NAME +" is not logging global resources."
            # The Trail named AWS_CLOUDTRAIL_NAME value is not multi-region -> NOT COMPLIANTfp
            elif correct_trail['IsMultiRegionTrail'] != True:
                result = False
                failReason = "The Trail named "+ AWS_CLOUDTRAIL_NAME +" is not logging in all regions."
            elif correct_trail['LogFileValidationEnabled'] != True:
                    result=False
                    failReason = "The Trail named " + AWS_CLOUDTRAIL_NAME + " has no log file integrity enabled."
            elif correct_trail_selector['ReadWriteType'] != 'All' or correct_trail_selector['IncludeManagementEvents'] != True:
                result=False
                failReason = "The Trail named " + AWS_CLOUDTRAIL_NAME + " do not log ALL Management events."
            elif True:#len(correct_trail_selector['DataResources']) != 0:
                if len(correct_trail_selector['DataResources']) == 0:
                    print("DataResources are empty")
                    result=False
                    failReason="The Trail named " + AWS_CLOUDTRAIL_NAME + " do not log any Data Events."
                else:
                    if str(correct_trail_selector['DataResources'][0]) != "{'Type': 'AWS::S3::Object', 'Values': ['arn:aws:s3']}":
                        result=False
                        failReason="The Trail named " + AWS_CLOUDTRAIL_NAME + " do not log ALL S3 Data Events."
            elif correct_trail['S3BucketName'] != True:
                result=False
                failReason = "The Trail named " + AWS_CLOUDTRAIL_NAME + " is not logging in the S3 bucket."
            elif 'KmsKeyId' not in correct_trail:
                result=False
                failReason = "The Trail named " + AWS_CLOUDTRAIL_NAME + " is not encrypted."
            else:
                result = False
                failReason = "The Trail named " + AWS_CLOUDTRAIL_NAME + " is active and well defined to send logs to " + AWS_CLOUDTRAIL_S3_BUCKET_NAME + " and proper encryption."
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    def LM_2_2_cloudwatch_event_bus_centralized(self):
        # This rule verifies that a defined Event Rule sends all events to a centralized Security Monitoring AWS Account.
        #
        # Scope
        # This rule covers all regions in one account from a single region and is triggered periodically.
        #
        # Prerequisites
        # Configure the following parameters in the Config Rules configuration:
        # 1) RoleToAssume [present by default]
        # Configure the following in the code of this lambda function
        # 2) AMAZON_CLOUDWATCH_EVENT_RULE_NAME [Name of the Rule to look for]
        # 3) AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID [Account ID of the centralized Security Monitoring Account, 12-digit]
        #
        # Use cases
        # The following logic is applied for each region:
        # No Event Rule is configured -> NOT COMPLIANT
        # No Event Rule named AMAZON_CLOUDWATCH_EVENT_RULE_NAME value is configured -> NOT COMPLIANT
        # The Event Rule named AMAZON_CLOUDWATCH_EVENT_RULE_NAME value is inactive -> NOT COMPLIANT
        # The Event Rule named AMAZON_CLOUDWATCH_EVENT_RULE_NAME value does not match the pattern "Send all events" -> NOT COMPLIANT
        # AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID is not a 12-digit string -> NOT COMPLIANT
        # The Event Rule named AMAZON_CLOUDWATCH_EVENT_RULE_NAME value has not exactly 1 target -> NOT COMPLIANT
        # The Event Rule named AMAZON_CLOUDWATCH_EVENT_RULE_NAME value has not for target the AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID default event bus -> NOT COMPLIANT
        # AMAZON_CLOUDWATCH_EVENT_RULE_NAME Event Rule is matching the pattern "Send all events" and send to AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID and is active -> COMPLIANT
        result = True
        failReason = ""
        offenders = []
        control = "2.2"
        description = "Cloud Trail Event Bus"
        scored = False
        offenders = []
        regions = boto3.client("ec2").describe_regions()['Regions']
        print(regions)
        for region in regions:
            eval = {}
            # region_session = get_sts_session(event, rule_parameters["RoleToAssume"], region['RegionName'])
            # events_client = region_session.client("events")

            # eval['Configuration'] = events_client.list_rules()['Rules']
            events_client = boto3.client('events')
            eval = events_client.list_rules()
            # eval = {'Rules': [{ "Type": "AWS::S3::Object", "Values": ["arn:aws:s3:::mybucket/prefix", "arn:aws:s3:::mybucket2/prefix2"] }], 'ResponseMetadata': {'RequestId': 'ae4e863e-389e-11e8-b8a0-a37af6e52e05', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': 'ae4e863e-389e-11e8-b8a0-a37af6e52e05', 'content-type': 'application/x-amz-json-1.1', 'content-length': '12', 'date': 'Thu, 05 Apr 2018 06:58:01 GMT'}, 'RetryAttempts': 0}}
            #AMAZON_CLOUDWATCH_EVENT_RULE_NAME = eval['Name']
            print("Marking eval")
            print(eval)
            print(eval['Rules'])
            if len(eval['Rules']) == 0:
                result = False
                failReason = "No Event Rule is configured in that region."
            else:
                for rule in eval['Rules']:
                    AMAZON_CLOUDWATCH_EVENT_RULE_NAME = rule['Name']
                    correct_rule =  events_client.describe_rule(Name=AMAZON_CLOUDWATCH_EVENT_RULE_NAME)
                    AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID = correct_rule['Arn'].split(":")[4]
                    print(correct_rule)
                    print(AMAZON_CLOUDWATCH_EVENT_RULE_NAME)
                    if correct_rule['State'] != 'ENABLED':
                        result = False
                        failReason = "The Event Rule name 4d " + AMAZON_CLOUDWATCH_EVENT_RULE_NAME + " is not enabled in that region."

                    elif correct_rule['EventPattern'] != '{"account":["' + correct_rule['Arn'].split(":")[4] + '"]}':
                        result = False
                        failReason = "The Event Rule named " + AMAZON_CLOUDWATCH_EVENT_RULE_NAME + " does not send all events (see EventPattern in that region."
                    else:
                        target = events_client.list_targets_by_rule(Rule=AMAZON_CLOUDWATCH_EVENT_RULE_NAME)["Targets"]
                        if len(target) != 1:
                          result = False
                          failReason = "The Event Rule named " + AMAZON_CLOUDWATCH_EVENT_RULE_NAME + " have no or too many targets."
                        elif target[0]["Arn"] != "arn:aws:events:" + region['RegionName'] + ":" + AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID + ":event-bus/default":
                            result = False
                            failReason = "The target of the Event Rule named " + AMAZON_CLOUDWATCH_EVENT_RULE_NAME + " is not the Event Bus of " + AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID + "."
                        else:
                            result = False
                            failReason = "The Event Rule named " + AMAZON_CLOUDWATCH_EVENT_RULE_NAME + " is active and well defined to send all events to " + AMAZON_CLOUDWATCH_EVENT_BUS_ACCOUNT_ID + " via Event Bus."

            return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                    'Description': description, 'ControlId': control}

    # 3.2 | vpc_no_route_to_igw
    def IS_3_2_vpc_main_route_table_no_igw(self):
        result = True
        failReason = ""
        offenders = []
        control = "3.2"
        description = "VPC main route table no igw"
        scored = False
        offenders = []
        ec2_client = boto3.client("ec2")

        route_tables = ec2_client.describe_route_tables(Filters=[{"Name": "association.main", "Values": ["true"]}])[
            'RouteTables']
        # print(route_tables)
        for route_table in route_tables:
            eval = {}
            eval["ComplianceResourceId"] = route_table['VpcId']

            igw_route = False
            for route in route_table['Routes']:
                if route['GatewayId'].startswith('igw-'):
                    igw_route = True

            if igw_route == False:
                result = True
                failReason = "No IGW route is present in the Main route table of this VPC."

            else:
                result = False
                failReason = "An IGW route is present in the Main route table of this VPC (RouteTableId: " +route_table['RouteTableId'] + ")."

            return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                    'Description': description, 'ControlId': control}

    # 4.1 | kms_cmk_rotation_activated
    def DP_4_1_kms_cmk_rotation_activated(self):
        result = True
        failReason = ""
        offenders = []
        control = "4.1"
        description = "Kms_cmk rotation keys"
        scored = False
        offenders = []
        configuration_item = {}

        regions = boto3.client("ec2").describe_regions()['Regions']
        for region in regions:
            # region_session = get_sts_session(event, rule_parameters["RoleToAssume"], region['RegionName'])
            kms_client = boto3.client('kms')
            keys = kms_client.list_keys()
            # print(keys)
            if len(keys['Keys']) == 0:
                continue
            else:
                for key in keys['Keys']:
                    eval = {}
                    eval["ComplianceResourceType"] = "AWS::KMS::Key"
                    eval["ComplianceResourceId"] = key['KeyArn']
                    if kms_client.describe_key(KeyId=key['KeyId'])["KeyMetadata"]["KeyManager"] == "AWS":
                        continue
                    if kms_client.get_key_rotation_status(KeyId=key['KeyId'])['KeyRotationEnabled'] == True:
                        result = True
                        failReason = "The yearly rotation is activated for this key."
                    else:
                        result = False
                        failReason = "The yearly rotation is not activated for this key."
                return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                            'Description': description, 'ControlId': control}

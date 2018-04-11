from __future__ import print_function
from awsscripter.common.LambdaBase import LambdaBase
from awsscripter.audit.CredReport import CredReport

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

from awsscripter.common.connection_manager import ConnectionManager
from awsscripter.common.helpers import get_external_stack_name
from awsscripter.hooks import add_audit_hooks
from awsscripter.resolvers import ResolvableProperty

# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

# =======
# Summary
# =======
#
# This AWS CloudFormation template gives insights on the compliance posture of the account where it is deployed.
#
# The set of Rules depends on the parameters you set during the deployment. Three RuleSets are available:
# - Security Baseline: Include best-practices rules ordered by their criticality.
# - PCI Guidance: Give guidance for achieving the Payment Card Industry Data Security Standard (PCI DSS).
# - High-Availability: Focus on the reliability of your environment.
#
# =============
# Prerequisites
# =============
#
# 1) The Compliance-as-code engine (https://github.com/awslabs/aws-config-engine-for-compliance-as-code) must be installed in the Compliance Account.
# 2) You must know the S3 Bucket Name where Config is centralized and the Account ID of the Compliance Account. Ideally, you should replace them in the template itself, as they are unlikely to change and it simplify scaling to other accounts.
#
# ================
# Baseline RuleSet
# ================
#
# The Baseline RuleSet provides guidance on the Security Epics of the AWS Cloud Adoption Framework (CAF). The Security Epics consist of groups of user stories (use cases and abuse cases) that you can work on during sprints. Each of these epics has multiple iterations addressing increasingly complex requirements and layering in robustness. Although we advise the use of agile, the epics can also be treated as general work streams or topics that help in prioritizing and structuring delivery using any other framework.
#
# This RuleSet has been designed to cover key baseline controls of a multi-account environment. It assumes that your AWS deployment follows Well-Architected best practices, including but not limited to:
# - Have a centralized Security Logging Account
# - Have a centralized Security Monitoring Account (it can be the same AWS Account)
#
# This RuleSet supports to:
# - classify an Application account by sensitivity (e.g. Sensitive, Confidential, etc.)
# - classify each Rule by criticality to allow prioritization of potential remediation (e.g. CRITICAL, HIGH, etc.)
#
# ====================
# PCI Guidance RuleSet
# ====================
#
# The PCI Guidance RuleSet provides guidance for achieving the Payment Card Industry Data Security Standard (PCI DSS) in AWS. This content is provided "as is" with no guarantees expressed or implied.  The content of this RuleSet is subject to change without notice. Likewise, future changes to the AWS environment may alter some of the guidance in this RuleSet. Your PCI assessor may have different interpretations and the guidance in this RuleSet. None of the content in this RuleSet is intended to replace or supersede the requirements of the PCI DSS.
#
# Intent: While this RuleSet discusses AWS aspects useful for validating PCI compliance readiness as well as formal compliance, it does not offer step-by-step instructions on conducting an assessment of an AWS environment.  However, it may assist QSAs in understanding how an AWS environment can be PCI-compliant.
#
# =========================
# High-Availability RuleSet
# =========================
#
# The High-Availability RuleSet provides guidance on the Reliability of the elements supporting your application. As addtionnal cost may occur, you may want to deploy this RuleSet only in appropriate environment.
#
# =======================
# Details of the RuleSets
# =======================
#
# The table below maps the RuleSets and the Rule:
#
# | --- | ------------------------------------ | ---------------- | -------- | ----------------- |
# |     |                                      | Baseline RuleSet | RuleSet  | Ruleset           |
# | Id  | Rule Name                            | by Account       | for PCI  | for               |
# |     |                                      | Classification   | guidance | High Availability |
# | --- | ------------------------------------ | ---------------- | -------- | ----------------- |
# | 1.1 | root_no_access                       | All              |          |                   |
# | 1.2 | root_mfa_enabled                     | All              | Yes      |                   |
# | 1.3 | root_no_access_key                   | All              |          |                   |
# | 1.4 | iam_policy_no_full_star              | All              | Yes      |                   |
# | 2.1 | cloudtrail_centralized_encrypted_lfi | All              | Yes      |                   |
# | 2.2 | cloudwatch_event_bus_centralized     | All              |          |                   |
# | 2.3 | config_enabled_centralized           | All              | Yes      |                   |
# | 2.4 | guardduty_enabled_centralized        | All              | Yes      |                   |
# | 3.1 | vpc_securitygroup_default_blocked    | All              |          |                   |
# | 3.2 | vpc_no_route_to_igw                  | All              |          |                   |
# | 3.3 | acm_certificate_expiry_90_days       | Private or above | Yes      |                   |
# | 4.1 | kms_cmk_rotation_activated           | Private or above | Yes      |                   |
# | 4.2 | s3_bucket_public_read_prohibited     | All              | Yes      |                   |
# | 4.3 | s3_bucket_public_write_prohibited    | All              |          |                   |
# | 4.4 | s3_bucket_ssl_requests_only          | Private or above | Yes      |                   |
# | 4.5 | ec2_ebs_volume_encrypted             | Private or above | Yes      |                   |
# | 4.6 | rds_storage_encrypted                | Private or above | Yes      |                   |
# | 6.1 | rds_multi_az_enabled                 |                  |          | Yes               |
# | 7.1 | compliance_ruleset_latest_installed  | All              |          |                   |
# | --- | ------------------------------------ | ---------------- | -------- | ----------------- |
#
# ====================
# Details of the Rules
# ====================
#
# The following rules are covered. The controls are organized by Security Epics of the AWS Cloud Adoption Framework:
#
# Identity and Access Management
# ==============================
# | Id  | Name                              | Type    | Criticity |
# | --- | --------------------------------- | ------- | --------- |
# | 1.1 | root_no_access                    | Custom  | CRITICAL  |
# | 1.2 | root_mfa_enabled                  | Custom  | CRITICAL  |
# | 1.3 | root_no_access_key                | Custom  | CRITICAL  |
# | 1.4 | iam_policy_no_full_star           | Custom  | HIGH      |
class PciAuditor(LambdaBase):
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

    def __init__(
            self, name, project_code, region, iam_role=None,
            parameters=None, awsscripter_user_data=None, hooks=None, s3_details=None,
            dependencies=None, role_arn=None, protected=False, tags=None,
            notifications=None, on_failure=None
    ):
        self.logger = logging.getLogger(__name__)
        self.name = name
        self.project_code = project_code
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
        #self.control=Control(parameters)

    def __repr__(self):
        return (
            "awsscripter.audit.audit.Audit("
            "project_code='{project_code}', region='{region}', "
            "iam_role='{iam_role}', parameters='{parameters}', "
            "awsscripter_user_data='{awsscripter_user_data}', "
            "hooks='{hooks}', s3_details='{s3_details}', "
            "dependencies='{dependencies}', role_arn='{role_arn}', "
            "protected='{protected}', tags='{tags}', "
            "notifications='{notifications}', on_failure='{on_failure}'"
            ")".format(
                project_code=self.project_code,
                region=self.connection_manager.region,
                iam_role=self.connection_manager.iam_role,
                parameters=self.parameters,
                awsscripter_user_data=self.awsscripter_user_data,
                hooks=self.hooks, s3_details=self.s3_details,
                dependencies=self.dependencies, role_arn=self.role_arn,
                protected=self.protected, tags=self.tags,
                notifications=self.notifications, on_failure=self.on_failure
            )
        )
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

    @add_audit_hooks
    def handle(self, event, context):
        # implementation
        self.logger.info("%s - Auditing Account", self.name)
        cred_reporter = CredReport("us-east-1")
        cred_report = cred_reporter.get_cred_report()
        #passpol = PasswordPolicy()
        #passwordpolicy = passpol.get_account_password_policy()
        #reglist = CloudTrail()
        #regions = reglist.get_regions()
        #print(regions)
        #region_list = reglist.get_regions()
        #cloud_trails = reglist.get_cloudtrails(regions)
        # Run individual controls.
        # Comment out unwanted controls
        #control1 = []
        #control1.append(self.control.control_1_1_root_use(cred_report))
        # control1.append(self.control.control_1_2_root_mfa_enabled())
        # control1.append(self.control.control_1_3_no_active_root_accesskey_used(cred_report))
        # control1.append(self.control.control_1_4_iam_policy_no_full_star())

        control2 = []
        control2.append(self.LM_2_1_cloudtrail_centralized_encrypted_lfi())
        # control2.append(self.control.control_2_1_ensure_cloud_trail_all_regions(cloud_trails))
        # control2.append(self.control.control_2_2_ensure_cloudtrail_validation(cloud_trails))
        # control2.append(self.control.control_2_3_ensure_cloudtrail_bucket_not_public(cloud_trails))
        # control2.append(self.control.control_2_4_ensure_cloudtrail_cloudwatch_logs_integration(cloud_trails))
        # control2.append(self.control.control_2_5_ensure_config_all_regions(regions))
        # control2.append(self.control.control_2_6_ensure_cloudtrail_bucket_logging(cloud_trails))
        # control2.append(self.control.control_2_7_ensure_cloudtrail_encryption_kms(cloud_trails))
        # control2.append(self.control.control_2_8_ensure_kms_cmk_rotation(regions))

        # control3 = []
        # control3.append(self.control.IS_3_1_vpc_securitygroup_default_blocked())
        # control3.append(self.control.IS_3_2_vpc_main_route_table_no_igw())
        # control3.append(self.control.control_3_3_ensure_log_metric_filter_root_usage(cloud_trails))
        # control3.append(self.control.control_3_4_ensure_log_metric_iam_policy_change(cloud_trails))
        # control3.append(self.control.control_3_5_ensure_log_metric_cloudtrail_configuration_changes(cloud_trails))
        # control3.append(self.control.control_3_6_ensure_log_metric_console_auth_failures(cloud_trails))
        # control3.append(self.control.control_3_7_ensure_log_metric_disabling_scheduled_delete_of_kms_cmk(cloud_trails))
        # control3.append(self.control.control_3_8_ensure_log_metric_s3_bucket_policy_changes(cloud_trails))
        # control3.append(self.control.control_3_9_ensure_log_metric_config_configuration_changes(cloud_trails))
        # control3.append(self.control.control_3_10_ensure_log_metric_security_group_changes(cloud_trails))
        # control3.append(self.control.control_3_11_ensure_log_metric_nacl(cloud_trails))
        # control3.append(self.control.control_3_12_ensure_log_metric_changes_to_network_gateways(cloud_trails))
        # control3.append(self.control.control_3_13_ensure_log_metric_changes_to_route_tables(cloud_trails))
        # control3.append(self.control.control_3_14_ensure_log_metric_changes_to_vpc(cloud_trails))
        # control3.append(self.control.control_3_15_verify_sns_subscribers())


        # control4 = []
        # control4.append(self.control.control_4_1_ensure_ssh_not_open_to_world(region_list))
        # control4.append(self.control.control_4_2_ensure_rdp_not_open_to_world(region_list))
        # control4.append(self.control.control_4_3_ensure_flow_logs_enabled_on_all_vpc(region_list))
        # control4.append(self.control.control_4_4_ensure_default_security_groups_restricts_traffic(region_list))
        # control4.append(self.control.control_4_5_ensure_route_tables_are_least_access(region_list))
        # Join results
        controls = []
        #controls.append(control1)
        controls.append(control2)
        controls.append(control3)
        # controls.append(control4)

        # Build JSON structure for console output if enabled
        if self.SCRIPT_OUTPUT_JSON:
            PciAuditor.json_output(controls)
    def json_output(controlResult):
        """Summary
        Args:
            controlResult (TYPE): Description
        Returns:
            TYPE: Description
        """
        inner = dict()
        outer = dict()
        for m in range(len(controlResult)):
            inner = dict()
            for n in range(len(controlResult[m])):
                x = int(controlResult[m][n]['ControlId'].split('.')[1])
                inner[x] = controlResult[m][n]
            y = controlResult[m][0]['ControlId'].split('.')[0]
            outer[y] = inner
        if PciAuditor.OUTPUT_ONLY_JSON is True:
            print(json.dumps(outer, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("JSON output:")
            print("-------------------------------------------------------")
            print(json.dumps(outer, sort_keys=True, indent=4, separators=(',', ': ')))
            print("-------------------------------------------------------")
            print("\n")
            print("Summary:")
            print(PciAuditor.shortAnnotation(controlResult))
            print("\n")
        return 0

    def shortAnnotation(controlResult):
        """Summary
        Args:
            controlResult (TYPE): Description
        Returns:
            TYPE: Description
        """
        annotation = []
        longAnnotation = False
        for m, _ in enumerate(controlResult):
            for n in range(len(controlResult[m])):
                if controlResult[m][n]['Result'] is False:
                    if len(str(annotation)) < 220:
                        annotation.append(controlResult[m][n]['ControlId'])
                    else:
                        longAnnotation = True
        if longAnnotation:
            annotation.append("etc")
            return "{\"Failed\":" + json.dumps(annotation) + "}"
        else:
            return "{\"Failed\":" + json.dumps(annotation) + "}"

    def send_results_to_sns(url):
        """Summary
        Args:
            url (TYPE): SignedURL created by the S3 upload function
        Returns:
            TYPE: Description
        """
        # Get correct region for the TopicARN
        region = (PciAuditor.SNS_TOPIC_ARN.split("sns:", 1)[1]).split(":", 1)[0]
        client = boto3.client('sns', region_name=region)
        client.publish(
            TopicArn=PciAuditor.SNS_TOPIC_ARN,
            Subject="AWS CIS Benchmark report - " + str(time.strftime("%c")),
            Message=json.dumps({'default': url}),
            MessageStructure='json'
        )

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
        control = "2.1"
        description = "Cloud Trail lfi"
        scored = False
        offenders = []
        cloudtrail_client = boto3.client("cloudtrail")

        # AWS_CLOUDTRAIL_NAME = 'Security_Trail_DO-NOT-MODIFY'

        eval = {}
        eval["Configuration"] = cloudtrail_client.describe_trails()['trailList']
        print(eval)

        if len(eval['Configuration']) == 0:
            result = False
            failReason = "No configuration Found."
            for trail in eval['Configuration']:
                AWS_CLOUDTRAIL_NAME=trail["Name"]
                result= "NON_COMPLIANT",
                failReason="No Trail named " + AWS_CLOUDTRAIL_NAME + " is configured."

            else:
                correct_trail_status = cloudtrail_client.get_trail_status(Name=AWS_CLOUDTRAIL_NAME)
                print(correct_trail_status)
                correct_trail = cloudtrail_client.describe_trails(trailNameList=[AWS_CLOUDTRAIL_NAME])['trailList'][0]
                print(correct_trail)
                AWS_CLOUDTRAIL_S3_BUCKET_NAME = correct_trail['S3BucketName']
                print(AWS_CLOUDTRAIL_S3_BUCKET_NAME)

                correct_trail_selector = cloudtrail_client.get_event_selectors(TrailName=AWS_CLOUDTRAIL_NAME)['EventSelectors'][0]
                print(correct_trail_selector)

                if correct_trail_status['IsLogging'] != True:
                     result =False,
                     failReason="The Trail named " + AWS_CLOUDTRAIL_NAME + " is not enabled."

                if 'LatestDeliveryError' in correct_trail_status:
                    result= False,
                    failReason= "The Trail named " + AWS_CLOUDTRAIL_NAME + " did not delivered the log as expected. The current error is " +correct_trail_status['LatestDeliveryError'] + ". Contact the Security team."

                elif correct_trail['IncludeGlobalServiceEvents'] != True:
                    result= False,
                    failReason= "The Trail named " + AWS_CLOUDTRAIL_NAME + " is not logging global resources."

                elif correct_trail['IsMultiRegionTrail'] != True:
                    result = False,
                    failReason ="The Trail named " + AWS_CLOUDTRAIL_NAME + " is not logging in all regions."

                elif correct_trail['LogFileValidationEnabled'] != True:
                        result = False,
                        failReason = "The Trail named " + AWS_CLOUDTRAIL_NAME + " has not log file integrity enabled."

                elif correct_trail_selector['ReadWriteType'] != 'All' or correct_trail_selector['IncludeManagementEvents'] != True:
                        result = False,
                        failReason ="The Trail named " + AWS_CLOUDTRAIL_NAME + " do not log ALL Management events."

                elif len(correct_trail_selector['DataResources'][0]) != "{'Type': 'AWS::S3::Object', 'Values': ['arn:aws:s3']}":
                        result= False,
                        failReason = "The Trail named " + AWS_CLOUDTRAIL_NAME + " do not log ALL S3 Data Events."
                # elif AWS_CLOUDTRAIL_S3_BUCKET_NAME == "":
                #     response = {
                #         "ComplianceType": "NON_COMPLIANT",
                #         "Annotation": "The parameter \"AWS_CLOUDTRAIL_S3_BUCKET_NAME\" is not defined in the lambda code. Contact the Security team."
                #     }
                elif correct_trail['S3BucketName'] != AWS_CLOUDTRAIL_S3_BUCKET_NAME:
                   result=False
                   failReason= "The Trail named " + AWS_CLOUDTRAIL_NAME + " is not logging in the S3 bucket named " + AWS_CLOUDTRAIL_S3_BUCKET_NAME + "."

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
                    result= False
                    failReason= "The Trail named " + AWS_CLOUDTRAIL_NAME + " is active and well defined to send logs to " + AWS_CLOUDTRAIL_S3_BUCKET_NAME + " and proper encryption."


        # eval["ComplianceResourceType"] = "AWS::CloudTrail::Trail"
        # eval["ComplianceResourceId"] = AWS_CLOUDTRAIL_NAME
        # eval["ComplianceType"] = response["ComplianceType"]
        # eval["Annotation"] = response["Annotation"]
        # eval["OrderingTimestamp"] = json.loads(event["invokingEvent"])['notificationCreationTime']
        # put_eval(eval, result_token)
            return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

# def IS_3_1_vpc_securitygroup_default_blocked():
#     result = True
#     failReason = ""
#     control = "3.1"
#     description = "vpc securitygroup"
#     scored = False
#     offenders = []
#     regions = boto3.client("ec2").describe_regions()['Regions']
#     for region in regions:
#         #region_session = get_sts_session(event, rule_parameters["RoleToAssume"], region['RegionName'])
#         ec2 = boto3.client("ec2")
#         security_groups = ec2.describe_security_groups()
#         print(security_groups)
#         for sg in security_groups['SecurityGroups']: # parsing all because filtering by GroupName returns a ClientError when there are no VPCs in the region
#             # print("sg is " + json.dumps(sg))
#             if 'VpcId' in sg and sg['GroupName'] == "default":
#                 eval = {}
#                 eval["ComplianceResourceType"] = "AWS::EC2::SecurityGroup"
#                 print(eval)
#                 eval['configuration'] = sg
#                 print(eval)
#                 event = {'Rules': [{'Name': 'frstrule', 'Arn': 'arn:aws:events:ap-south-1:413075340967:rule/frstrule', 'EventPattern': '{"source":["aws.cloudtrail"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["cloudtrail.amazonaws.com"]}}', 'State': 'ENABLED', 'Description': 'checking CloudTrails API call at cloudwatch'}], 'ResponseMetadata': {'RequestId': 'a3ef3df0-3bb3-11e8-938e-df5f76c798bd', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': 'a3ef3df0-3bb3-11e8-938e-df5f76c798bd', 'content-type': 'application/x-amz-json-1.1', 'content-length': '331', 'date': 'Mon, 09 Apr 2018 05:05:36 GMT'}, 'RetryAttempts': 0}}
#
#                 eval["ComplianceResourceId"] = "arn:aws:ec2:" + region['RegionName'] + ":" + event['configRuleArn'].split(":")[4] + ":security_group/" + sg['GroupId']
#                 #there is no configrulearn passed in event
#                 print(eval)
#                 if  len(eval['configuration']['IpPermissions']):
#                     result= "NON_COMPLIANT",
#                     failReason= "There are permissions on the ingress of this security group."
#
#                 elif len(eval['configuration']['IpPermissionsEgress']):
#
#                     result= "NON_COMPLIANT",
#                     failReason= "There are permissions on the egress of this security group."
#
#                 else:
#                    result= "COMPLIANT",
#                    failReason="This security group has no permission."
#
#                 # eval["ComplianceResourceType"] = "AWS::EC2::SecurityGroup"
#                 # eval["ComplianceType"]=response["ComplianceType"]
#                 # eval["Annotation"]=response["Annotation"]
#                 # eval["OrderingTimestamp"]=json.loads(event["invokingEvent"])['notificationCreationTime']
#                 # put_eval(eval, result_token)
#                 return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
#                         'Description': description, 'ControlId': control}
# def IS_3_2_vpc_main_route_table_no_igw():
#     result = True
#     failReason = ""
#     control = "3.2"
#     description = "vpc main route table "
#     scored = False
#     offenders = []
#     ec2_client = boto3.client("ec2")
#
#     route_tables = ec2_client.describe_route_tables(Filters=[{"Name": "association.main", "Values": ["true"]}])['RouteTables']
#     print(route_tables)
#     for route_table in route_tables:
#         eval = {}
#         eval["ComplianceResourceId"] = route_table['VpcId']
#         print(eval)
#         igw_route = False
#         for route in route_table['Routes']:
#             if route['GatewayId'].startswith('igw-'):
#                 igw_route = True
#         if igw_route == False:
#             result = "COMPLIANT",
#             failReason= "No IGW route is present in the Main route table of this VPC."
#         else:
#             result= "NON_COMPLIANT",
#             failReason="An IGW route is present in the Main route table of this VPC (RouteTableId: " +route_table['RouteTableId'] + ")."
#
#         return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
#                  'Description': description, 'ControlId': control}



# input values for args and/or kwargs
auditor = PciAuditor("myname", "myproject", "us-east-1")
auditor.handle("test","test")
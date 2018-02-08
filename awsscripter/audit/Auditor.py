"""Implementation of a Lambda handler as a class for a specific Lambda function.
The Lambda function is deployed with handler set to MyLambdaClass.handler.
Class fields will persist across invocations for a given Lambda container,
and so are a good way to implement caching.
An instance of the class is created for each invocation, so instance fields can
be set from the input without the data persisting."""
from __future__ import print_function
from awsscripter.common.LambdaBase import LambdaBase
from awsscripter.audit.CredReport import CredReport
from awsscripter.audit.PasswordPolicy import PasswordPolicy
from awsscripter.audit.CloudTrail import CloudTrail

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

class Auditor(LambdaBase):
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
        passpol = PasswordPolicy()
        passwordpolicy =passpol.get_account_password_policy()
        reglist=CloudTrail()
        regions=reglist.get_regions()
        region_list=reglist.get_regions()
        cloud_trails=reglist.get_cloudtrails(regions)
        # Run individual controls.
        # Comment out unwanted controls
        control1 = []
        control1.append(self.control_1_1_root_use(cred_report))
        control1.append(self.control_1_5_password_policy_uppercase(passwordpolicy))

        control2 = []
        control2.append(self.control_2_1_ensure_cloud_trail_all_regions(cloud_trails))

        control4 = []
        control4.append(self.control_4_1_ensure_ssh_not_open_to_world(region_list))

        # Join results
        controls = []
        controls.append(control1)
        controls.append(control2)

        # Build JSON structure for console output if enabled
        if self.SCRIPT_OUTPUT_JSON:
            Auditor.json_output(controls)


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

    # 1.5 Ensure IAM password policy requires at least one uppercase letter (Scored)
    def control_1_5_password_policy_uppercase(self, passwordpolicy):
        """Summary

        Args:
            passwordpolicy (TYPE): Description

        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "1.5"
        description = "Ensure IAM password policy requires at least one uppercase letter"
        scored = True
        if passwordpolicy is False:
            result = False
            failReason = "Account does not have a IAM password policy."
        else:
            if passwordpolicy['RequireUppercaseCharacters'] is False:
                result = False
                failReason = "Password policy does not require at least one uppercase letter"
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    # 2.1 Ensure CloudTrail is enabled in all regions (Scored)
    def control_2_1_ensure_cloud_trail_all_regions(self,cloudtrails):
            """Summary

            Args:
                cloudtrails (TYPE): Description

            Returns:
                TYPE: Description
            """
            result = False
            failReason = ""
            offenders = []
            control = "2.1"
            description = "Ensure CloudTrail is enabled in all regions"
            scored = True
            for m, n in cloudtrails.items():
                for o in n:
                    if o['IsMultiRegionTrail']:
                        client = boto3.client('cloudtrail', region_name=m)
                        response = client.get_trail_status(
                            Name=o['TrailARN']
                        )
                        if response['IsLogging'] is True:
                            result = True
                            break
            if result is False:
                failReason = "No enabled multi region trails found"
            return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                    'Description': description, 'ControlId': control}

    def control_4_1_ensure_ssh_not_open_to_world(self,regions):
        """Summary

        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "4.1"
        description = "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"
        scored = True
        for n in regions:
            client = boto3.client('ec2', region_name=n)
            response = client.describe_security_groups()
            for m in response['SecurityGroups']:
                if "0.0.0.0/0" in str(m['IpPermissions']):
                    for o in m['IpPermissions']:
                        try:
                            if int(o['FromPort']) <= 22 <= int(o['ToPort']) and '0.0.0.0/0' in str(o['IpRanges']):
                                result = False
                                failReason = "Found Security Group with port 22 open to the world (0.0.0.0/0)"
                                offenders.append(str(m['GroupId']))
                        except:
                            if str(o['IpProtocol']) == "-1" and '0.0.0.0/0' in str(o['IpRanges']):
                                result = False
                                failReason = "Found Security Group with port 22 open to the world (0.0.0.0/0)"
                                offenders.append(str(n) + " : " + str(m['GroupId']))
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

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
        if Auditor.OUTPUT_ONLY_JSON is True:
            print(json.dumps(outer, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("JSON output:")
            print("-------------------------------------------------------")
            print(json.dumps(outer, sort_keys=True, indent=4, separators=(',', ': ')))
            print("-------------------------------------------------------")
            print("\n")
            print("Summary:")
            print(Auditor.shortAnnotation(controlResult))
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
        region = (Auditor.SNS_TOPIC_ARN.split("sns:", 1)[1]).split(":", 1)[0]
        client = boto3.client('sns', region_name=region)
        client.publish(
            TopicArn=Auditor.SNS_TOPIC_ARN,
            Subject="AWS CIS Benchmark report - " + str(time.strftime("%c")),
            Message=json.dumps({'default': url}),
            MessageStructure='json'
        )


# input values for args and/or kwargs
auditor = Auditor("myname", "myproject", "us-east-1")
auditor.handle("test","test")

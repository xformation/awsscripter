"""Implementation of a Lambda handler as a class for a specific Lambda function.
The Lambda function is deployed with handler set to MyLambdaClass.handler.
Class fields will persist across invocations for a given Lambda container,
and so are a good way to implement caching.
An instance of the class is created for each invocation, so instance fields can
be set from the input without the data persisting."""
from __future__ import print_function
from awsscripter.common.LambdaBase import LambdaBase
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

class MyLambdaClass(LambdaBase):
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
        self.logger.info("%s - Creating stack", self.name)
        cred_report = self.get_cred_report()
        # Run individual controls.
        # Comment out unwanted controls
        control1 = []
        control1.append(self.control_1_1_root_use(cred_report))
        # Build JSON structure for console output if enabled
        if self.SCRIPT_OUTPUT_JSON:
            json_output(controls)

        # Create HTML report file if enabled
        if self.S3_WEB_REPORT:
            htmlReport = json2html(controls, accountNumber)
            if S3_WEB_REPORT_OBFUSCATE_ACCOUNT:
                for n, _ in enumerate(htmlReport):
                    htmlReport[n] = re.sub(r"\d{12}", "111111111111", htmlReport[n])
            signedURL = s3report(htmlReport, accountNumber)
            if self.OUTPUT_ONLY_JSON is False:
                print("SignedURL:\n" + signedURL)
            if self.SEND_REPORT_URL_TO_SNS is True:
                send_results_to_sns(signedURL)

        # Report back to Config if we detected that the script is initiated from Config Rules
        if self.configRule:
            evalAnnotation = shortAnnotation(controls)
            set_evaluation(invokingEvent, event, evalAnnotation)

    def get_cred_report(self):
        """Summary

        Returns:
            TYPE: Description
        """
        perform_audit_kwargs = {
            "Parameters": self._format_parameters(self.parameters),
            "Capabilities": ['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'],
            "NotificationARNs": self.notifications,
            "Tags": [
                {"Key": str(k), "Value": str(v)}
                for k, v in self.tags.items()
            ]
        }
        if self.on_failure:
            perform_audit_kwargs.update({"OnFailure": self.on_failure})
        x = 0
        status = ""
        while self.connection_manager.call(
            service="iam",
            command="generate_credential_report",
            kwargs=perform_audit_kwargs
        ) != "COMPLETE":
            time.sleep(2)
            x += 1
            # If no credentail report is delivered within this time fail the check.
            if x > 10:
                status = "Fail: rootUse - no CredentialReport available."
                break
        if "Fail" in status:
            return status
        response = self.connection_manager.call(
            service="iam",
            command="get_credential_report",
            kwargs=perform_audit_kwargs
        )
        self.logger.debug("Response is ", response)
        report = []
        splitted_contents = response['Content'].splitlines()
        splitted_contents = [x.decode('UTF8') for x in splitted_contents]
        reader = csv.DictReader(splitted_contents, delimiter=',')
        for row in reader:
            report.append(row)

        # Verify if root key's never been used, if so add N/A
        try:
            if report[0]['access_key_1_last_used_date']:
                pass
        except:
            report[0]['access_key_1_last_used_date'] = "N/A"
        try:
            if report[0]['access_key_2_last_used_date']:
                pass
        except:
            report[0]['access_key_2_last_used_date'] = "N/A"
        return report

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


# input values for args and/or kwargs
handler = MyLambdaClass("myname", "myproject", "us-east-1")
handler.handle("test","test")

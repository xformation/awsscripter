"""Implementation of a Lambda handler as a class for a specific Lambda function.
The Lambda function is deployed with handler set to MyLambdaClass.handler.
Class fields will persist across invocations for a given Lambda container,
and so are a good way to implement caching.
An instance of the class is created for each invocation, so instance fields can
be set from the input without the data persisting."""
from __future__ import print_function
from awsscripter.common.LambdaBase import LambdaBase
from awsscripter.audit.CredReport import CredReport
from awsscripter.hippa.PasswordPolicy import PasswordPolicy
from awsscripter.hippa.CloudTrail import CloudTrail
from awsscripter.hippa.Controls import Control

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
import yaml

from awsscripter.common.connection_manager import ConnectionManager
from awsscripter.common.helpers import get_external_stack_name
from awsscripter.hooks import add_audit_hooks
from awsscripter.resolvers import ResolvableProperty

class HippaAuditor(LambdaBase):
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
        self.control=Control(parameters)

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
        passwordpolicy = passpol.get_account_password_policy()
        reglist = CloudTrail()
        regions = reglist.get_regions()
        #print(regions)
        region_list = reglist.get_regions()
        cloud_trails = reglist.get_cloudtrails(regions)
        # Run individual controls.
        # Comment out unwanted controls
        control1 = []
        control1.append(self.control.control_1_1_root_use(cred_report))
        # control1.append(self.control.control_1_2_mfa_on_password_enabled_iam(cred_report))
        # control1.append(self.control.control_1_3_unused_credentials(cred_report)) #i have to disable this
        # control1.append(self.control.control_1_4_rotated_keys(cred_report))
        # control1.append(self.control.control_1_5_password_policy_uppercase(passwordpolicy))
        # control1.append(self.control.control_1_6_password_policy_lowercase(passwordpolicy))
        # control1.append(self.control.control_1_7_password_policy_symbol(passwordpolicy))
        # control1.append(self.control.control_1_8_password_policy_number(passwordpolicy))
        # control1.append(self.control.control_1_9_password_policy_length(passwordpolicy))
        # control1.append(self.control.control_1_10_password_policy_reuse(passwordpolicy))
        # control1.append(self.control.control_1_11_password_policy_expire(passwordpolicy))
        # control1.append(self.control.control_1_12_root_key_exists(cred_report))
        # control1.append(self.control.control_1_13_root_mfa_enabled())
        # control1.append(self.control.control_1_14_root_hardware_mfa_enabled())
        # control1.append(self.control.control_1_15_security_questions_registered())
        # control1.append(self.control.control_1_16_no_policies_on_iam_users())
        # control1.append(self.control.control_1_17_detaile  d_billing_enabled())
        # control1.append(self.control.control_1_18_ensure_iam_master_and_manager_roles())
        # control1.append(self.control.control_1_19_maintain_current_contact_details())
        # control1.append(self.control.control_1_21_ensure_iam_instance_roles_used())
        # control1.append(self.control.control_1_22_ensure_incident_management_roles())
        # control1.append(self.control.control_1_23_no_active_initial_access_keys_with_iam_user(cred_report))
        # control1.append(self.control.control_1_24_no_overly_permissive_policies())
        #
        #
        # control2 = []
        # control2.append(self.control.control_2_1_ensure_cloud_trail_all_regions(cloud_trails))
        # control2.append(self.control.control_2_2_ensure_cloudtrail_validation(cloud_trails))
        # control2.append(self.control.control_2_3_ensure_cloudtrail_bucket_not_public(cloud_trails))
        # control2.append(self.control.control_2_4_ensure_cloudtrail_cloudwatch_logs_integration(cloud_trails))
        # control2.append(self.control.control_2_5_ensure_config_all_regions(regions))
        # control2.append(self.control.control_2_6_ensure_cloudtrail_bucket_logging(cloud_trails))
        # control2.append(self.control.control_2_7_ensure_cloudtrail_encryption_kms(cloud_trails))
        # control2.append(self.control.control_2_8_ensure_kms_cmk_rotation(regions))
        #
        # control3 = []
        # control3.append(self.control.control_3_1_ensure_log_metric_filter_unauthorized_api_calls(cloud_trails))
        # control3.append(self.control.control_3_2_ensure_log_metric_filter_console_signin_no_mfa(cloud_trails))
        # control3.append(self.control.control_3_3_ensure_log_metric_filter_root_usage(cloud_trails))
        # control3.append(self.control.control_3_4_ensure_log_metric_iam_policy_change(cloud_trails))
        # control3.append(self.control.control_3_5_ensure_log_metric_cloudtrail_configuration_changes(cloud_trails))
        # # control3.append(self.control.control_3_6_ensure_log_metric_console_auth_failures(cloud_trails))
        # control3.append(self.control.control_3_7_ensure_log_metric_disabling_scheduled_delete_of_kms_cmk(cloud_trails))
        # control3.append(self.control.control_3_8_ensure_log_metric_s3_bucket_policy_changes(cloud_trails))
        # control3.append(self.control.control_3_9_ensure_log_metric_config_configuration_changes(cloud_trails))
        # # control3.append(self.control.control_3_10_ensure_log_metric_security_group_changes(cloud_trails))
        # control3.append(self.control.control_3_11_ensure_log_metric_nacl(cloud_trails))
        # control3.append(self.control.control_3_12_ensure_log_metric_changes_to_network_gateways(cloud_trails))
        # control3.append(self.control.control_3_13_ensure_log_metric_changes_to_route_tables(cloud_trails))
        # control3.append(self.control.control_3_14_ensure_log_metric_changes_to_vpc(cloud_trails))
        # control3.append(self.control.control_3_15_verify_sns_subscribers())
        #
        #
        # control4 = []
        # control4.append(self.control.control_4_1_ensure_ssh_not_open_to_world(region_list))
        # control4.append(self.control.control_4_2_ensure_rdp_not_open_to_world(region_list))
        # control4.append(self.control.control_4_3_ensure_flow_logs_enabled_on_all_vpc(region_list))
        # control4.append(self.control.control_4_4_ensure_default_security_groups_restricts_traffic(region_list))
        # control4.append(self.control.control_4_5_ensure_route_tables_are_least_access(region_list))
        # Join results
        control5 = []
        # control5.append(self.control.control_5_1_ensure_Dynamodb_SSE_enabled(regions))
        # control5.append(self.control.control_5_2_db_on_instance_storage_encrypted(regions))
        # control5.append(self.control.control_5_10_mfa_all_users(cred_report))
        control5.append(self.control.control_5_5_enforce_password_policy())
        control5.append(self.control.control_5_13_s3_bucket_encryption_read_actions())


        controls = []
        controls.append(control1)
        # controls.append(control2)
        # controls.append(control3)
        # controls.append(control4)
        controls.append(control5)

        # Build JSON structure for console output if enabled
        if self.SCRIPT_OUTPUT_JSON:
            HippaAuditor.json_output(controls)
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
        if HippaAuditor.OUTPUT_ONLY_JSON is True:
            print(json.dumps(outer, sort_keys=True, indent=4, separators=(',', ': ')))
        else:
            print("JSON output:")
            print("-------------------------------------------------------")
            print(json.dumps(outer, sort_keys=True, indent=4, separators=(',', ': ')))
            print("-------------------------------------------------------")
            print("\n")
            print("Summary:")
            print(HippaAuditor.shortAnnotation(controlResult))
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
        region = (HippaAuditor.SNS_TOPIC_ARN.split("sns:", 1)[1]).split(":", 1)[0]
        client = boto3.client('sns', region_name=region)
        client.publish(
            TopicArn=HippaAuditor.SNS_TOPIC_ARN,
            Subject="AWS CIS Benchmark report - " + str(time.strftime("%c")),
            Message=json.dumps({'default': url}),
            MessageStructure='json'
        )
auditor = HippaAuditor("myname", "myproject", "us-east-1")
auditor.handle("test","test")
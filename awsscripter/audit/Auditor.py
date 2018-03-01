""""Implementation of a Lambda handler as a class for a specific Lambda function.
The Lambda function is deployed with handler set to MyLambdaClass.handler.
Class fields will persist across invocations for a given Lambda container,
and so are a good way to implement caching.
An instance of the class is created for each invocation, so instance fields can
be set from the input without the data persisting."""
from __future__ import print_function

#from awsscripter.audit.audit import Audit

from coverage import results
from os.path import join

from moto.ec2.responses import vpcs
from s3transfer import subscribers
from troposphere import Join

from awsscripter.common.connection_manager import ConnectionManager
from awsscripter.common.LambdaBase import LambdaBase
from awsscripter.audit.CredReport import CredReport
from awsscripter.audit.PasswordPolicy import PasswordPolicy

from awsscripter.audit.CloudTrails import CloudTrail

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
        passwordpolice = PasswordPolicy()
        passwordpolicy = passwordpolice.get_account_password_policy()
        regionlists = CloudTrail()
        regions = regionlists.get_regions()
        cloud_trails = regionlists.get_cloudtrails(regions)

        # Run individual controls.
        # Comment out unwanted controls
        control3 = []
        control3.append(self.control_3_1_ensure_log_metric_filter_unauthorized_api_calls(cloud_trails))
        control3.append(self.control_3_2_ensure_log_metric_filter_console_signin_no_mfa(cloud_trails))
        control3.append(self.control_3_3_ensure_log_metric_filter_root_usage(cloud_trails))
        control3.append(self.control_3_4_ensure_log_metric_iam_policy_change(cloud_trails))
        control3.append(self.control_3_5_ensure_log_metric_cloudtrail_configuration_changes(cloud_trails))
        control3.append(self.control_3_6_ensure_log_metric_console_auth_failures(cloud_trails))
        control3.append(self.control_3_7_ensure_log_metric_disabling_scheduled_delete_of_kms_cmk(cloud_trails))
        control3.append(self.control_3_8_ensure_log_metric_s3_bucket_policy_changes(cloud_trails))
        control3.append(self.control_3_9_ensure_log_metric_config_configuration_changes(cloud_trails))
        control3.append(self.control_3_10_ensure_log_metric_security_group_changes(cloud_trails))
        control3.append(self.control_3_11_ensure_log_metric_nacl(cloud_trails))
        control3.append(self.control_3_12_ensure_log_metric_changes_to_network_gateways(cloud_trails))
        control3.append(self.control_3_13_ensure_log_metric_changes_to_route_tables(cloud_trails))
        control3.append(self.control_3_14_ensure_log_metric_changes_to_vpc(cloud_trails))
        control3.append(self.control_3_15_verify_sns_subscribers())
        control4 = []
        control4.append(self.control_4_1_ensure_ssh_not_open_to_world(regions))
        control4.append(self.control_4_2_ensure_rdp_not_open_to_world(regions))
        control4.append(self.control_4_3_ensure_flow_logs_enabled_on_all_vpc(regions))
        control4.append(self.control_4_4_ensure_default_security_groups_restricts_traffic(regions))
        control4.append(self.control_4_5_ensure_route_tables_are_least_access(regions))

        controls = []
        controls.append(control3)
        controls.append(control4)
        # Build JSON structure for console output if enabled
        if self.SCRIPT_OUTPUT_JSON:
            Auditor.json_output(controls)

            # --- Monitoring ---

            # 3.1 Ensure a log metric filter and alarm exist for unauthorized API calls (Scored)

    def control_3_1_ensure_log_metric_filter_unauthorized_api_calls(self, cloudtrails):
        """Summary

        Returns:
            TYPE: Description
        """
        result = False
        failReason = ""
        offenders = []
        control = "3.1"
        description = "Ensure log metric filter unauthorized api calls"
        scored = True
        failReason = "Incorrect log metric alerts for unauthorized_api_calls"
        for m, n in cloudtrails.items():

            for o in n:
                try:

                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        #client = connection_manager.client('logs', region_name=m)
                        self.setRegion(region, iam_role=None)
                        cloud_kwargs = {
                            'logGroupName' : group,

                        }
                        filters = self.connection_manager.call(
                            service='logs',
                            command='describe_metric_filters',
                            kwargs=cloud_kwargs
                        )
                        """
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )"""
                        for p in filters['metricFilters']:
                            patterns = ["\$\.errorCode\s*=\s*\"?\*UnauthorizedOperation(\"|\)|\s)",
                                        "\$\.errorCode\s*=\s*\"?AccessDenied\*(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern'])):
                                #cwclient = connection_manager.client('cloudwatch', region_name=m)
                                MetricName = p['metricTransformations'][0]['metricName'],
                                Namespace = p['metricTransformations'][0]['metricNamespace']

                                cloud_kwargs = {
                                    'MetricName' : MetricName,
                                    'Namespace' : Namespace,


                                }
                                response = self.connection_manager.call(
                                    service='cloudwatch',
                                    command='describe_alarms_for_metric',
                                    kwargs=cloud_kwargs
                                )
                                """response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )"""
                                TopicArn = response['MetricAlarms'][0]['AlarmActions'][0]

                                cloud_kwargs = {
                                    'TopicArn':TopicArn,

                                }
                                subscribers = self.connection_manager.call(
                                    service='cloudwatch',
                                    command='list_subscriptions_by_topic',
                                    kwargs=cloud_kwargs
                                )
                                """snsClient = connection_manager.client('sns', region_name=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )"""
                                if not len(subscribers['Subscriptions']) == 0:
                                    result = True
                except:
                    pass
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

        # 3.2 Ensure a log metric filter and alarm exist for Management Console sign-in without MFA (Scored)
    def control_3_2_ensure_log_metric_filter_console_signin_no_mfa(self, cloudtrails):
            """Summary

            Returns:
                TYPE: Description
            """
            result = False
            failReason = ""
            offenders = []
            control = "3.2"
            description = "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA"
            scored = True
            failReason = "Incorrect log metric alerts for management console signin without MFA"
            for m, n in cloudtrails.items():
                for o in n:
                    try:
                        if o['CloudWatchLogsLogGroupArn']:
                            group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                            self.setRegion(region, iam_role=None)
                            cloud_kwargs = {
                                'logGroupName': group,

                            }
                            filters = self.connection_manager.call(
                                service='logs',
                                command='describe_metric_filters',
                                kwargs=cloud_kwargs
                            )
                            """
                            client = connection_manager.client('logs', region_name=m)
                            filters = client.describe_metric_filters(
                                logGroupName=group
                            )"""
                            for p in filters['metricFilters']:
                                patterns = ["\$\.eventName\s*=\s*\"?ConsoleLogin(\"|\)|\s)",
                                            "\$\.additionalEventData\.MFAUsed\s*\!=\s*\"?Yes"]
                                if find_in_string(patterns, str(p['filterPattern'])):
                                    MetricName = p['metricTransformations'][0]['metricName'],
                                    Namespace = p['metricTransformations'][0]['metricNamespace']

                                    cloud_kwargs = {
                                        'MetricName': MetricName,
                                        'Namespace': Namespace,


                                    }
                                    response = self.connection_manager.call(
                                        service='cloudwatch',
                                        command='describe_alarms_for_metric',
                                        kwargs=cloud_kwargs
                                    )
                                    """
                                    cwclient = connection_manager.client('cloudwatch', region_name=m)
                                    response = cwclient.describe_alarms_for_metric(
                                        MetricName=p['metricTransformations'][0]['metricName'],
                                        Namespace=p['metricTransformations'][0]['metricNamespace']
                                    )"""

                                    TopicArn = response['MetricAlarms'][0]['AlarmActions'][0]

                                    cloud_kwargs = {
                                        'TopicArn': TopicArn,

                                    }
                                    subscribers = self.connection_manager.call(
                                        service='cloudwatch',
                                        command='list_subscriptions_by_topic',
                                        kwargs=cloud_kwargs
                                    )
                                    """
                                    snsClient = connection_manager.client('sns', region_name=m)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                        #  Pagination not used since only 1 subscriber required
                                    )"""

                                    if not len(subscribers['Subscriptions']) == 0:
                                        result = True
                    except:
                        pass
            return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                    'Description': description, 'ControlId': control}
            # 3.3 Ensure a log metric filter and alarm exist for usage of "root" account (Scored)

    def control_3_3_ensure_log_metric_filter_root_usage(self, cloudtrails):
        """Summary

        Returns:
            TYPE: Description
        """
        result = False
        failReason = ""
        offenders = []
        control = "3.3"
        description = "Ensure a log metric filter and alarm exist for root usage"
        scored = True
        failReason = "Incorrect log metric alerts for root usage"
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        #client = connection_manager.client('logs', region_name=m)
                        self.setRegion(region, iam_role=None)
                        cloud_kwargs={
                            'logGroupName' : group,

                        }
                        """
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )"""
                        filters= self.connection_manager.call(
                        service='logs',
                        command='describe_metric_filters',
                        kwargs= cloud_kwargs
                        )
                        for p in filters['metricFilters']:
                            patterns = ["\$\.userIdentity\.type\s*=\s*\"?Root",
                                        "\$\.userIdentity\.invokedBy\s*NOT\s*EXISTS",
                                        "\$\.eventType\s*\!=\s*\"?AwsServiceEvent(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern'])):
                                MetricName = p['metricTransformations'][0]['metricName'],
                                Namespace = p['metricTransformations'][0]['metricNamespace']

                                cloud_kwargs = {
                                    'MetricName':MetricName,
                                    'Namespace':Namespace,

                                }
                                response = self.connection_manager.call(
                                    service='cloudwatch',
                                    command='describe_alarms_for_metric',
                                    kwargs=cloud_kwargs
                                )
                                """
                                cwclient = connection_manager.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )"""

                                TopicArn = response['MetricAlarms'][0]['AlarmActions'][0]

                                cloud_kwargs={
                                    'TopicArn':TopicArn,

                                }
                                subscribers = self.connection_manager.call(
                                    service='sns',
                                    command='list_subscriptions_by_topic',
                                    kwargs=cloud_kwargs
                                )
                                """snsClient = connection_manager.client('sns', region_name=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )"""
                                if not len(subscribers['Subscriptions']) == 0:
                                    result = True
                except:
                    pass
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

        # 3.4 Ensure a log metric filter and alarm exist for IAM policy changes  (Scored)

    def control_3_4_ensure_log_metric_iam_policy_change(self, cloudtrails):
        """Summary

        Returns:
            TYPE: Description
        """
        result = False
        failReason = ""
        offenders = []
        control = "3.4"
        description = "Ensure a log metric filter and alarm exist for IAM changes"
        scored = True
        failReason = "Incorrect log metric alerts for IAM policy changes"
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        self.setRegion(region, iam_role=None)
                        cloud_kwargs = {
                            'logGroupName': group,

                        }
                        subscribers = self.connection_manager.call(
                            service='logs',
                            command='describe_metric_filters',
                            kwargs=cloud_kwargs
                        )
                        """
                        client = connection_manager.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )"""

                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?DeleteGroupPolicy(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteRolePolicy(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteUserPolicy(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?PutGroupPolicy(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?PutRolePolicy(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?PutUserPolicy(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?CreatePolicy(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeletePolicy(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?CreatePolicyVersion(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeletePolicyVersion(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?AttachRolePolicy(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DetachRolePolicy(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?AttachUserPolicy(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DetachUserPolicy(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?AttachGroupPolicy(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DetachGroupPolicy(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern'])):
                                MetricName = p['metricTransformations'][0]['metricName'],
                                Namespace = p['metricTransformations'][0]['metricNamespace']

                                cloud_kwargs = {
                                    'MetricName': MetricName,
                                    'Namespace': Namespace,

                                }
                                response = self.connection_manager.call(
                                    service='cloudwatch',
                                    command='describe_alarms_for_metric',
                                    kwargs=cloud_kwargs
                                )
                                """
                                cwclient = connection_manager.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )"""
                                TopicArn = response['MetricAlarms'][0]['AlarmActions'][0]

                                cloud_kwargs = {
                                    'TopicArn': TopicArn,

                                }
                                response = self.connection_manager.call(
                                    service='sns',
                                    command='list_subscriptions_by_topic',
                                    kwargs=cloud_kwargs
                                )
                                """
                                snsClient = connection_manager.client('sns', region_name=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )"""

                                if not len(subscribers['Subscriptions']) == 0:
                                    result = True
                except:
                    pass
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

        # 3.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes (Scored)

    def control_3_5_ensure_log_metric_cloudtrail_configuration_changes(self, cloudtrails):
        """Summary

        Returns:
            TYPE: Description
        """
        result = False
        failReason = ""
        offenders = []
        control = "3.5"
        description = "Ensure a log metric filter and alarm exist for CloudTrail configuration changes"
        scored = True
        failReason = "Incorrect log metric alerts for CloudTrail configuration changes"
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        self.setRegion(region, iam_role=None)
                        cloud_kwargs={
                            'logGroupName' : group,

                        }
                        filters=self.connection_manager.call(
                            service='logs',
                            command='describe_metric_filters',
                            kwargs=cloud_kwargs

                        )
                        """client = connection_manager.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )"""
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?CreateTrail(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?UpdateTrail(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteTrail(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?StartLogging(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?StopLogging(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern'])):
                                MetricName = p['metricTransformations'][0]['metricName'],
                                Namespace = p['metricTransformations'][0]['metricNamespace']


                                cloud_kwargs={
                                    'MetricName':MetricName,
                                    'Namespace':Namespace
                                }
                                response=self.connection_manager.call(
                                    service='cloudwatch',
                                    command='describe_alarms_for_metric',
                                    kwargs=cloud_kwargs
                                )
                                """cwclient = connection_manager.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )"""

                                TopicArn = response['MetricAlarms'][0]['AlarmActions'][0]
                                m = 'us-east-1'
                                cloud_kwargs = {
                                    'TopicArn':TopicArn,
                                    'region_name':m
                                }
                                subscribers=self.connection_manager.call(
                                    service='sns',
                                    command='list_subscriptions_by_topic',
                                    kwargs=cloud_kwargs
                                )
                                """
                                snsClient = connection_manager.client('sns', region_name=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )"""
                                if not len(subscribers['Subscriptions']) == 0:
                                    result = True
                except:
                    pass
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

        # 3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures (Scored)

    def control_3_6_ensure_log_metric_console_auth_failures(self, cloudtrails):
        """Summary

        Returns:
            TYPE: Description
        """
        result = False
        failReason = ""
        offenders = []
        control = "3.6"
        description = "Ensure a log metric filter and alarm exist for console auth failures"
        scored = True
        failReason = "Ensure a log metric filter and alarm exist for console auth failures"
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        self.setRegion(region, iam_role=None)
                        cloud_kwargs = {
                            'logGroupName': group,

                        }
                        filters = self.connection_manager.call(
                            service='logs',
                            command='describe_metric_filters',
                            kwargs=cloud_kwargs

                        )
                        """
                        client = connection_manager.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )"""

                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?ConsoleLogin(\"|\)|\s)",
                                        "\$\.errorMessage\s*=\s*\"?Failed authentication(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern'])):
                                MetricName = p['metricTransformations'][0]['metricName'],
                                Namespace = p['metricTransformations'][0]['metricNamespace']


                                cloud_kwargs = {
                                    'MetricName': MetricName,
                                    'Namespace': Namespace
                                }
                                response = self.connection_manager.call(
                                    service='cloudwatch',
                                    command='describe_alarms_for_metric',
                                    kwargs=cloud_kwargs
                                )
                                """
                                cwclient = connection_manager.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )"""
                                TopicArn = response['MetricAlarms'][0]['AlarmActions'][0]

                                cloud_kwargs = {
                                    'TopicArn': TopicArn,

                                }
                                response = self.connection_manager.call(
                                    service='sns',
                                    command='list_subscriptions_by_topic',
                                    kwargs=cloud_kwargs
                                )
                                """
                                snsClient = connection_manager.client('sns', region_name=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )"""

                                if not len(subscribers['Subscriptions']) == 0:
                                    result = True
                except:
                    pass
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

        # 3.7 Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs (Scored)

    def control_3_7_ensure_log_metric_disabling_scheduled_delete_of_kms_cmk(self, cloudtrails):
        """Summary

        Returns:
            TYPE: Description
        """
        result = False
        failReason = ""
        offenders = []
        control = "3.7"
        description = "Ensure a log metric filter and alarm exist for disabling or scheduling deletion of KMS CMK"
        scored = True
        failReason = "Ensure a log metric filter and alarm exist for disabling or scheduling deletion of KMS CMK"
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        self.setRegion(region, iam_role=None)
                        cloud_kwargs = {
                            'logGroupName': group,

                        }
                        filters = self.connection_manager.call(
                            service='logs',
                            command='describe_metric_filters',
                            kwargs=cloud_kwargs

                        )
                        """
                        client = connection_manager.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )"""
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventSource\s*=\s*\"?kms\.amazonaws\.com(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DisableKey(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?ScheduleKeyDeletion(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern'])):
                                MetricName = p['metricTransformations'][0]['metricName'],
                                Namespace = p['metricTransformations'][0]['metricNamespace']


                                cloud_kwargs = {
                                    'MetricName': MetricName,
                                    'Namespace': Namespace
                                }
                                response = self.connection_manager.call(
                                    service='cloudwatch',
                                    command='describe_alarms_for_metric',
                                    kwargs=cloud_kwargs
                                )

                                """
                                cwclient = connection_manager.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )"""
                                TopicArn = response['MetricAlarms'][0]['AlarmActions'][0]

                                cloud_kwargs = {
                                    'TopicArn': TopicArn,

                                }
                                subscribers = self.connection_manager.call(
                                    service='sns',
                                    command='list_subscriptions_by_topic',
                                    kwargs=cloud_kwargs
                                )
                                """
                                snsClient = connection_manager.client('sns', region_name=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )"""
                                if not len(subscribers['Subscriptions']) == 0:
                                    result = True
                except:
                    pass
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

        # 3.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes (Scored)

    def control_3_8_ensure_log_metric_s3_bucket_policy_changes(self, cloudtrails):
        """Summary

        Returns:
            TYPE: Description
        """
        result = False
        failReason = ""
        offenders = []
        control = "3.8"
        description = "Ensure a log metric filter and alarm exist for S3 bucket policy changes"
        scored = True
        failReason = "Ensure a log metric filter and alarm exist for S3 bucket policy changes"
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        self.setRegion(region, iam_role=None)
                        cloud_kwargs = {
                            'logGroupName': group,

                        }
                        filters = self.connection_manager.call(
                            service='logs',
                            command='describe_metric_filters',
                            kwargs=cloud_kwargs

                        )
                        """
                        client = connection_manager.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )"""

                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventSource\s*=\s*\"?s3\.amazonaws\.com(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?PutBucketAcl(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?PutBucketPolicy(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?PutBucketCors(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?PutBucketLifecycle(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?PutBucketReplication(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteBucketPolicy(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteBucketCors(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteBucketLifecycle(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteBucketReplication(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern'])):
                                MetricName = p['metricTransformations'][0]['metricName'],
                                Namespace = p['metricTransformations'][0]['metricNamespace']


                                cloud_kwargs = {
                                    'MetricName': MetricName,
                                    'Namespace': Namespace
                                }
                                response = self.connection_manager.call(
                                    service='cloudwatch',
                                    command='describe_alarms_for_metric',
                                    kwargs=cloud_kwargs
                                )
                                """
                                cwclient = connection_manager.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )"""
                                TopicArn = response['MetricAlarms'][0]['AlarmActions'][0]

                                cloud_kwargs = {
                                    'TopicArn': TopicArn,

                                }
                                subscribers = self.connection_manager.call(
                                    service='sns',
                                    command='list_subscriptions_by_topic',
                                    kwargs=cloud_kwargs
                                )
                                """
                                snsClient = connection_manager.client('sns', region_name=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )"""

                                if not len(subscribers['Subscriptions']) == 0:
                                    result = True
                except:
                    pass
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

        # 3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes (Scored)

    def control_3_9_ensure_log_metric_config_configuration_changes(self, cloudtrails):
        """Summary

        Returns:
            TYPE: Description
        """
        result = False
        failReason = ""
        offenders = []
        control = "3.9"
        description = "Ensure a log metric filter and alarm exist for for AWS Config configuration changes"
        scored = True
        failReason = "Ensure a log metric filter and alarm exist for for AWS Config configuration changes"
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        self.setRegion(region, iam_role=None)
                        cloud_kwargs = {
                            'logGroupName': group,
                        }
                        filters = self.connection_manager.call(
                            service='logs',
                            command='describe_metric_filters',
                            kwargs=cloud_kwargs

                        )
                        """
                        client = connection_manager.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )"""
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventSource\s*=\s*\"?config\.amazonaws\.com(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?StopConfigurationRecorder(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteDeliveryChannel(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?PutDeliveryChannel(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?PutConfigurationRecorder(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern'])):
                                MetricName = p['metricTransformations'][0]['metricName'],
                                Namespace = p['metricTransformations'][0]['metricNamespace']


                                cloud_kwargs = {
                                    'MetricName': MetricName,
                                    'Namespace': Namespace
                                }
                                response = self.connection_manager.call(
                                    service='cloudwatch',
                                    command='describe_alarms_for_metric',
                                    kwargs=cloud_kwargs
                                )
                                """
                                cwclient = connection_manager.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )"""

                                TopicArn = response['MetricAlarms'][0]['AlarmActions'][0]

                                cloud_kwargs = {
                                    'TopicArn': TopicArn,
                                    'region_name': m
                                }
                                subscribers = self.connection_manager.call(
                                    service='sns',
                                    command='list_subscriptions_by_topic',
                                    kwargs=cloud_kwargs
                                )
                                """
                                snsClient = connection_manager.client('sns', region_name=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )"""

                                if not len(subscribers['Subscriptions']) == 0:
                                    result = True
                except:
                    pass
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

        # 3.10 Ensure a log metric filter and alarm exist for security group changes (Scored)

    def control_3_10_ensure_log_metric_security_group_changes(self, cloudtrails):
        """Summary

        Returns:
            TYPE: Description
        """
        result = False
        failReason = ""
        offenders = []
        control = "3.10"
        description = "Ensure a log metric filter and alarm exist for security group changes"
        scored = True
        failReason = "Ensure a log metric filter and alarm exist for security group changes"
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        self.setRegion(region, iam_role=None)
                        cloud_kwargs = {
                            'logGroupName': group,

                        }
                        filters = self.connection_manager.call(
                            service='logs',
                            command='describe_metric_filters',
                            kwargs=cloud_kwargs

                        )
                        """
                        client = connection_manager.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )"""
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?AuthorizeSecurityGroupIngress(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?AuthorizeSecurityGroupEgress(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?RevokeSecurityGroupIngress(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?RevokeSecurityGroupEgress(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?CreateSecurityGroup(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteSecurityGroup(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern'])):
                                MetricName = p['metricTransformations'][0]['metricName'],
                                Namespace = p['metricTransformations'][0]['metricNamespace']


                                cloud_kwargs = {
                                    'MetricName': MetricName,
                                    'Namespace': Namespace
                                }
                                response = self.connection_manager.call(
                                    service='cloudwatch',
                                    command='describe_alarms_for_metric',
                                    kwargs=cloud_kwargs
                                )
                                """
                                cwclient = connection_manager.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )"""
                                TopicArn = response['MetricAlarms'][0]['AlarmActions'][0]

                                cloud_kwargs = {
                                    'TopicArn': TopicArn,

                                }
                                subscribers = self.connection_manager.call(
                                    service='sns',
                                    command='list_subscriptions_by_topic',
                                    kwargs=cloud_kwargs
                                )
                                """
                                snsClient = connection_manager.client('sns', region_name=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )"""

                                if not len(subscribers['Subscriptions']) == 0:
                                    result = True
                except:
                    pass
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

        # 3.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) (Scored)

    def control_3_11_ensure_log_metric_nacl(self, cloudtrails):
        """Summary

        Returns:
            TYPE: Description
        """
        result = False
        failReason = ""
        offenders = []
        control = "3.11"
        description = "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)"
        scored = True
        failReason = "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)"
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        self.setRegion(region, iam_role=None)
                        cloud_kwargs = {
                            'logGroupName': group,

                        }
                        filters = self.connection_manager.call(
                            service='logs',
                            command='describe_metric_filters',
                            kwargs=cloud_kwargs

                        )
                        """
                        client = connection_manager.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )"""
                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?CreateNetworkAcl(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?CreateNetworkAclEntry(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteNetworkAcl(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteNetworkAclEntry(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?ReplaceNetworkAclEntry(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?ReplaceNetworkAclAssociation(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern'])):
                                MetricName = p['metricTransformations'][0]['metricName'],
                                Namespace = p['metricTransformations'][0]['metricNamespace']


                                cloud_kwargs = {
                                    'MetricName': MetricName,
                                    'Namespace': Namespace
                                }
                                response = self.connection_manager.call(
                                    service='cloudwatch',
                                    command='describe_alarms_for_metric',
                                    kwargs=cloud_kwargs
                                )
                                """
                                cwclient = connection_manager.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )"""
                                TopicArn = response['MetricAlarms'][0]['AlarmActions'][0]

                                cloud_kwargs = {
                                    'TopicArn': TopicArn,

                                }
                                subscribers = self.connection_manager.call(
                                    service='sns',
                                    command='list_subscriptions_by_topic',
                                    kwargs=cloud_kwargs
                                )
                                """
                                snsClient = connection_manager.client('sns', region_name=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )"""

                                if not len(subscribers['Subscriptions']) == 0:
                                    result = True
                except:
                    pass
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

        # 3.12 Ensure a log metric filter and alarm exist for changes to network gateways (Scored)

    def control_3_12_ensure_log_metric_changes_to_network_gateways(self, cloudtrails):
        """Summary

        Returns:
            TYPE: Description
        """
        result = False
        failReason = ""
        offenders = []
        control = "3.12"
        description = "Ensure a log metric filter and alarm exist for changes to network gateways"
        scored = True
        failReason = "Ensure a log metric filter and alarm exist for changes to network gateways"
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        self.setRegion(region, iam_role=None)
                        cloud_kwargs = {
                            'logGroupName': group,

                        }
                        filters = self.connection_manager.call(
                            service='logs',
                            command='describe_metric_filters',
                            kwargs=cloud_kwargs

                        )
                        """
                        client = connection_manager.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )"""

                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?CreateCustomerGateway(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteCustomerGateway(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?AttachInternetGateway(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?CreateInternetGateway(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteInternetGateway(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DetachInternetGateway(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern'])):
                                MetricName = p['metricTransformations'][0]['metricName'],
                                Namespace = p['metricTransformations'][0]['metricNamespace']


                                cloud_kwargs = {
                                    'MetricName': MetricName,
                                    'Namespace': Namespace
                                }
                                response = self.connection_manager.call(
                                    service='cloudwatch',
                                    command='describe_alarms_for_metric',
                                    kwargs=cloud_kwargs
                                )
                                """
                                cwclient = connection_manager.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )"""
                                TopicArn = response['MetricAlarms'][0]['AlarmActions'][0]

                                cloud_kwargs = {
                                    'TopicArn': TopicArn,

                                }
                                subscribers = self.connection_manager.call(
                                    service='sns',
                                    command='list_subscriptions_by_topic',
                                    kwargs=cloud_kwargs
                                )
                                """
                                snsClient = connection_manager.client('sns', region_name=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )"""

                                if not len(subscribers['Subscriptions']) == 0:
                                    result = True
                except:
                    pass
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

        # 3.13 Ensure a log metric filter and alarm exist for route table changes (Scored)

    def control_3_13_ensure_log_metric_changes_to_route_tables(self, cloudtrails):
        """Summary

        Returns:
            TYPE: Description
        """
        result = False
        failReason = ""
        offenders = []
        control = "3.13"
        description = "Ensure a log metric filter and alarm exist for route table changes"
        scored = True
        failReason = "Ensure a log metric filter and alarm exist for route table changes"
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)
                        self.setRegion(region, iam_role=None)
                        cloud_kwargs = {
                            'logGroupName': group,

                        }
                        filters = self.connection_manager.call(
                            service='logs',
                            command='describe_metric_filters',
                            kwargs=cloud_kwargs

                        )
                        """
                        client = connection_manager.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )"""

                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?CreateRoute(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?CreateRouteTable(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?ReplaceRoute(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?ReplaceRouteTableAssociation(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteRouteTable(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteRoute(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DisassociateRouteTable(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern'])):
                                MetricName = p['metricTransformations'][0]['metricName'],
                                Namespace = p['metricTransformations'][0]['metricNamespace']

                                cloud_kwargs = {
                                    'MetricName': MetricName,
                                    'Namespace': Namespace,

                                }
                                response = self.connection_manager.call(
                                    service='cloudwatch',
                                    command='describe_alarms_for_metric',
                                    kwargs=cloud_kwargs
                                )
                                """
                                cwclient = connection_manager.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )"""
                                TopicArn = response['MetricAlarms'][0]['AlarmActions'][0]
                                m = 'us-east-1'
                                cloud_kwargs = {
                                    'TopicArn': TopicArn,

                                }
                                response = self.connection_manager.call(
                                    service='sns',
                                    command='list_subscriptions_by_topic',
                                    kwargs=cloud_kwargs
                                )
                                """
                                snsClient = connection_manager.client('sns', region_name=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )"""

                                if not len(subscribers['Subscriptions']) == 0:
                                    result = True
                except:
                    pass
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

        # 3.14 Ensure a log metric filter and alarm exist for VPC changes (Scored)

    def control_3_14_ensure_log_metric_changes_to_vpc(self, cloudtrails):
        """Summary

        Returns:
            TYPE: Description
        """
        result = False
        failReason = ""
        offenders = []
        control = "3.14"
        description = "Ensure a log metric filter and alarm exist for VPC changes"
        scored = True
        failReason = "Ensure a log metric filter and alarm exist for VPC changes"
        for m, n in cloudtrails.items():
            for o in n:
                try:
                    if o['CloudWatchLogsLogGroupArn']:
                        group = re.search('log-group:(.+?):', o['CloudWatchLogsLogGroupArn']).group(1)

                        cloud_kwargs = {
                            'logGroupName': group,

                        }
                        filters = self.connection_manager.call(
                            service='logs',
                            command='describe_metric_filters',
                            kwargs=cloud_kwargs

                        )
                        """
                        client = connection_manager.client('logs', region_name=m)
                        filters = client.describe_metric_filters(
                            logGroupName=group
                        )"""

                        for p in filters['metricFilters']:
                            patterns = ["\$\.eventName\s*=\s*\"?CreateVpc(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteVpc(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?ModifyVpcAttribute(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?AcceptVpcPeeringConnection(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?CreateVpcPeeringConnection(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DeleteVpcPeeringConnection(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?RejectVpcPeeringConnection(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?AttachClassicLinkVpc(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DetachClassicLinkVpc(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?DisableVpcClassicLink(\"|\)|\s)",
                                        "\$\.eventName\s*=\s*\"?EnableVpcClassicLink(\"|\)|\s)"]
                            if find_in_string(patterns, str(p['filterPattern'])):
                                MetricName = p['metricTransformations'][0]['metricName'],
                                Namespace = p['metricTransformations'][0]['metricNamespace']

                                cloud_kwargs = {
                                    'MetricName': MetricName,
                                    'Namespace': Namespace,

                                }
                                response = self.connection_manager.call(
                                    service='cloudwatch',
                                    command='describe_alarms_for_metric',
                                    kwargs=cloud_kwargs
                                )
                                """
                                cwclient = connection_manager.client('cloudwatch', region_name=m)
                                response = cwclient.describe_alarms_for_metric(
                                    MetricName=p['metricTransformations'][0]['metricName'],
                                    Namespace=p['metricTransformations'][0]['metricNamespace']
                                )"""
                                TopicArn = response['MetricAlarms'][0]['AlarmActions'][0]

                                cloud_kwargs = {
                                    'TopicArn': TopicArn,
                                }
                                response = self.connection_manager.call(
                                    service='sns',
                                    command='list_subscriptions_by_topic',
                                    kwargs=cloud_kwargs
                                )
                                """
                                snsClient = connection_manager.client('sns', region_name=m)
                                subscribers = snsClient.list_subscriptions_by_topic(
                                    TopicArn=response['MetricAlarms'][0]['AlarmActions'][0]
                                    #  Pagination not used since only 1 subscriber required
                                )"""

                                if not len(subscribers['Subscriptions']) == 0:
                                    result = True
                except:
                    pass
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

        # 3.15 Ensure appropriate subscribers to each SNS topic (Not Scored)

    def control_3_15_verify_sns_subscribers(self):
        """Summary

        Returns:
            TYPE: Description
        """
        result = "Manual"
        failReason = ""
        offenders = []
        control = "3.15"
        description = "Ensure appropriate subscribers to each SNS topic, please verify manually"
        scored = False
        failReason = "Control not implemented using API, please verify manually"
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    def control_4_1_ensure_ssh_not_open_to_world(self, regions):
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
            """client = boto3.client('ec2', region_name=n)
            response = client.describe_security_groups()"""
            cloud_kwargs = None
            response = self.connection_manager.call(
                service='ec2',
                command='describe_security_groups',
                kwargs=cloud_kwargs
            )
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

    # 4.2 Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 (Scored)
    def control_4_2_ensure_rdp_not_open_to_world(self, regions):
        """Summary

        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "4.2"
        description = "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389"
        scored = True
        for n in regions:
            """client = boto3.client('ec2', region_name=n)
            response = client.describe_security_groups()"""
            cloud_kwargs = None
            response = self.connection_manager.call(
                service='ec2',
                command='describe_security_groups',
                kwargs=cloud_kwargs
            )
            for m in response['SecurityGroups']:
                if "0.0.0.0/0" in str(m['IpPermissions']):
                    for o in m['IpPermissions']:
                        try:
                            if int(o['FromPort']) <= 3389 <= int(o['ToPort']) and '0.0.0.0/0' in str(o['IpRanges']):
                                result = False
                                failReason = "Found Security Group with port 3389 open to the world (0.0.0.0/0)"
                                offenders.append(str(m['GroupId']))
                        except:
                            if str(o['IpProtocol']) == "-1" and '0.0.0.0/0' in str(o['IpRanges']):
                                result = False
                                failReason = "Found Security Group with port 3389 open to the world (0.0.0.0/0)"
                                offenders.append(str(n) + " : " + str(m['GroupId']))
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    # 4.3 Ensure VPC flow logging is enabled in all VPCs (Scored)
    def control_4_3_ensure_flow_logs_enabled_on_all_vpc(self, regions):
        """Summary

        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "4.3"
        description = "Ensure VPC flow logging is enabled in all VPCs"
        scored = True
        for n in regions:
            """client = boto3.client('ec2', region_name=n)
            flowlogs = client.describe_flow_logs(
                #  No paginator support in boto atm.
            )"""
            fl_kwargs = None
            flowlogs = self.connection_manager.call (
            service = 'ec2',
            command = 'describe_flow_logs',
            kwargs = fl_kwargs
            )
            activeLogs = []
            for m in flowlogs['FlowLogs']:
                if "vpc-" in str(m['ResourceId']):
                    activeLogs.append(m['ResourceId'])
            #vpcs = client.describe_vpcs(

                cloud_kwargs = {
                    'Filters' : [
                    {
                        'Name': 'state',
                        'Values': [
                            'available',
                        ]
                    },

                ]
                }
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    # 4.4 Ensure the default security group of every VPC restricts all traffic (Scored)
    def control_4_4_ensure_default_security_groups_restricts_traffic(self, regions):
        """Summary

        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "4.4"
        description = "Ensure the default security group of every VPC restricts all traffic"
        scored = True
        for n in regions:
            """client = boto3.client('ec2', region_name=n)
            response = client.describe_security_groups"""
            cloud_kwargs = {
                'Filters' : [
                    {
                        'Name': 'group-name',
                        'Values': [
                            'default',
                        ]
                    },
                ]
            }
            response = self.connection_manager.call(
            service = 'ec2',
            command = 'describe_security_groups',
            kwargs = cloud_kwargs
            )
            for m in response['SecurityGroups']:
                if not (len(m['IpPermissions']) + len(m['IpPermissionsEgress'])) == 0:
                    result = False
                    failReason = "Default security groups with ingress or egress rules discovered"
                    offenders.append(str(n) + " : " + str(m['GroupId']))
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    # 4.5 Ensure routing tables for VPC peering are "least access" (Not Scored)
    def control_4_5_ensure_route_tables_are_least_access(self, regions):
        """Summary

        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "4.5"
        description = "Ensure routing tables for VPC peering are least access"
        scored = False
        for n in regions:
           """ client = boto3.client('ec2', region_name=n)
            response = client.describe_route_tables()"""
        ec2_kwargs = None
        response = self.connectionmanager.call(
        service = 'ec2',
        command = 'describe_route_tables',
        kwargs = ec2_kwargs
        )
            
        for m in response['RouteTables']:
                for o in m['Routes']:
                    try:
                        if o['VpcPeeringConnectionId']:
                            if int(str(o['DestinationCidrBlock']).split("/", 1)[1]) < 24:
                                result = False
                                failReason = "Large CIDR block routed to peer discovered, please investigate"
                                offenders.append(str(n) + " : " + str(m['RouteTableId']))
                    except:
                        pass
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    # 4.5 Ensure routing tables for VPC peering are "least access" (Not Scored)
    def control_4_5_ensure_route_tables_are_least_access(self, regions):
        """Summary

        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "4.5"
        description = "Ensure routing tables for VPC peering are least access"
        scored = False
        for n in regions:
            """client = boto3.client('ec2', region_name=n)
            response = client.describe_route_tables()"""
            ec2_kwargs = None
            response = self.connection_manager.call(
                service= 'ec2',
                command = 'describe_route_tables',
                kwargs = ec2_kwargs
            )
            for m in response['RouteTables']:
                for o in m['Routes']:
                    try:
                        if o['VpcPeeringConnectionId']:
                            if int(str(o['DestinationCidrBlock']).split("/", 1)[1]) < 24:
                                result = False
                                failReason = "Large CIDR block routed to peer discovered, please investigate"
                                offenders.append(str(n) + " : " + str(m['RouteTableId']))
                    except:
                        pass
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    def setRegion(self, region, iam_role=None):
        self.connection_manager = ConnectionManager(region,iam_role)

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
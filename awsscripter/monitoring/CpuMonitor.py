"""Implementation of a Audit function as a class for crdential report generations.
An instance of the class is created for each invocation, so instance fields can
be set from the input without the data persisting."""
import csv
import logging
import time
from datetime import datetime, timedelta

import botocore
from dateutil.tz import tzutc

from awsscripter.audit.audit_status import AuditStatus
from awsscripter.common.AwsBase import AwsBase
from awsscripter.common.connection_manager import ConnectionManager
from awsscripter.common.exceptions import UnknownAuditStatusError


class CpuMonitor(AwsBase):

    def __init__(
            self, region, iam_role=None,
            parameters=None, awsscripter_user_data=None, hooks=None, s3_details=None,
            dependencies=None, role_arn=None, protected=False, tags=None,
            notifications=None, on_failure=None
    ):
        self.logger = logging.getLogger(__name__)
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
            "awsscripter.monitoring.CpuMonitor.CpuMonitor("
            "region='{region}', "
            "iam_role='{iam_role}', parameters='{parameters}', "
            "awsscripter_user_data='{awsscripter_user_data}', "
            "hooks='{hooks}', s3_details='{s3_details}', "
            "dependencies='{dependencies}', role_arn='{role_arn}', "
            "protected='{protected}', tags='{tags}', "
            "notifications='{notifications}', on_failure='{on_failure}'"
            ")".format(
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


    def get_status(self):
        """
        Returns the credential report generation status.

        :returns: The stack's status.
        :rtype: awsscripter.stack.stack_status.StackStatus
        :raises: awsscripter.common.exceptions.StackDoesNotExistError
        """
        try:
            perform_audit_kwargs = {
                "Parameters": self._format_parameters(self.parameters),
                "Capabilities": ['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'],
                "NotificationARNs": self.notifications,
                "Tags": [
                    {"Key": str(k), "Value": str(v)}
                    for k, v in self.tags.items()
                ]
            }
            status = self.connection_manager.call(
                service="iam",
                command="generate_credential_report",
                kwargs=perform_audit_kwargs
            )['State']
        except botocore.exceptions.ClientError as exp:
            raise exp
        return status

    def _wait_for_completion(self):
        """
        Waits for a credential report generarion operation to finish. Prints iam events
        while it waits.

        :returns: The final audit status.
        :rtype: awsscripter.audit.audit_status.AuditStatus
        """
        status = AuditStatus.IN_PROGRESS

        self.most_recent_event_datetime = (
            datetime.now(tzutc()) - timedelta(seconds=3)
        )
        while status == AuditStatus.IN_PROGRESS:
            status = self._get_simplified_status(self.get_status())
            time.sleep(4)
        return status

    def show_cpu_usage_result(self):
        """Summary

        Returns:
            TYPE: Description
        """
        self.generate_cred_report();
        perform_audit_kwargs = {
            "Parameters": self._format_parameters(self.parameters),
            "Capabilities": ['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM'],
            "NotificationARNs": self.notifications,
            "Tags": [
                {"Key": str(k), "Value": str(v)}
                for k, v in self.tags.items()
            ]
        }
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

    def generate_cred_report(self):
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
        response = self.connection_manager.call(
            service="iam",
            command="generate_credential_report",
            kwargs=perform_audit_kwargs
        )
        self.logger.debug(
            "Generated credential report response: %s", response
        )
        status = self._wait_for_completion()
        return status



    @staticmethod
    def _get_simplified_status(status):
        """
        Returns the simplified Stack Status.

        The simplified stack status is represented by the struct
        ``awsscripter.stack.stackStatus()`` and can take one of the following options:

        * STARTED
        * INPROGRESS
        * "COMPLETE"

        :param status: The CloudFormation stack status to simplify.
        :type status: str
        :returns: The stack's simplified status
        :rtype: awsscripter.stack.stack_status.StackStatus
        """
        if status.endswith("STARTED"):
            return AuditStatus.STARTED
        elif status.endswith("INPROGRESS"):
            return AuditStatus.IN_PROGRESS
        elif status.endswith("COMPLETE"):
            return AuditStatus.COMPLETE
        else:
            raise UnknownAuditStatusError(
                "{0} is unknown".format(status)
            )

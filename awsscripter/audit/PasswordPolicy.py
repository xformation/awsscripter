
from __future__ import print_function
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

from awsscripter.audit.audit import Audit
from awsscripter.common.connection_manager import ConnectionManager
from awsscripter.common.helpers import get_external_stack_name
from awsscripter.hooks import add_audit_hooks
from awsscripter.resolvers import ResolvableProperty


class PasswordPolicy():
    def __init__(
            self, region= "us-east-1", iam_role=None,
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
            "awsscripter.audit.CredReport.CredReport("
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

    def get_account_password_policy(self):
        """Check if a IAM password policy exists, if not return false

        Returns:
            Account IAM password policy or Falsel
        """
        try:
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
            # response = Audit.IAM_CLIENT.get_account_password_policy()
            response = self.connection_manager.call(
                service="iam",
                command="get_account_password_policy",
                kwargs=perform_audit_kwargs
            )
            return response['PasswordPolicy']
        except Exception as e:
            if "cannot be found" in str(e):
                return False


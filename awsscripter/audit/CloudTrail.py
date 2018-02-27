import csv
import logging
import time
import boto3
from datetime import datetime, timedelta

import botocore
from dateutil.tz import tzutc

from awsscripter.audit.audit_status import AuditStatus
from awsscripter.common.AwsBase import AwsBase
from awsscripter.common.connection_manager import ConnectionManager
from awsscripter.common.exceptions import UnknownAuditStatusError
class CloudTrail():

    def __init__(
            self, region="us-east-1", iam_role=None,
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

    def setRegion(self,region,iam_role=None):
        self.connection_manager = ConnectionManager(region, iam_role)


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
                command="get_account_password_policy",
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
    #@classmethod
    def get_regions(self):
        """Summary

        Returns:
        TYPE: Description
        """
        perform_audit_kwargs = None

        #client = boto3.client('ec2')
        #client = self.connection_manager._get_client('ec2')
        region_response = self.connection_manager.call(
                service="ec2",
                command="describe_regions",
                kwargs=perform_audit_kwargs
            )
        #region_response = client.describe_regions()
        regions = [region['RegionName'] for region in region_response['Regions']]
        return regions

    def get_cloudtrails(self, regions):
        """Summary
        Returns:
            TYPE: Description
        """
        trails = dict()
        for region in regions:
            #print(region)
            self.setRegion(region,iam_role=None)
            cloudtrail_kwargs = None
            response = self.connection_manager.call(
                service="cloudtrail",
                command="describe_trails",
                kwargs=cloudtrail_kwargs
            )
            #print(response)
            temp = []
            for m in response['trailList']:
                print(response['trailList'])
                if m['IsMultiRegionTrail'] is True:
                    if m['HomeRegion'] == region:
                        temp.append(m)
                else:
                    temp.append(m)
            if len(temp) > 0:
                trails[region] = temp
            print(trails)
        return trails


"""Implementation of a Audit function as a class for crdential report generations.
An instance of the class is created for each invocation, so instance fields can
be set from the input without the data persisting."""

from awsscripter.common.AwsBase import AwsBase
import logging
from awsscripter.common.connection_manager import ConnectionManager
import botocore


class CredReport(AwsBase):
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

    def _format_parameters(parameters):
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
        Returns the stack's status.

        :returns: The stack's status.
        :rtype: awsscripter.stack.stack_status.StackStatus
        :raises: awsscripter.common.exceptions.StackDoesNotExistError
        """
        try:
            status = self.describe()["Stacks"][0]["StackStatus"]
        except botocore.exceptions.ClientError as exp:
            raise exp
        return status

    def _wait_for_completion(self):
        """
        Waits for a stack operation to finish. Prints CloudFormation events
        while it waits.

        :returns: The final stack status.
        :rtype: awsscripter.stack.stack_status.StackStatus
        """
        status = StackStatus.IN_PROGRESS

        self.most_recent_event_datetime = (
            datetime.now(tzutc()) - timedelta(seconds=3)
        )
        while status == StackStatus.IN_PROGRESS:
            status = self._get_simplified_status(self.get_status())
            self._log_new_events()
            time.sleep(4)
        return status

import csv
import logging
import time
from datetime import datetime, timedelta

import botocore
from dateutil.tz import tzutc

from awsscripter.audit.audit import Audit
from awsscripter.audit.audit_status import AuditStatus
from awsscripter.common.AwsBase import AwsBase
from awsscripter.common.connection_manager import ConnectionManager
from awsscripter.common.exceptions import UnknownAuditStatusError
class PasswordPolicy():
    def get_account_password_policy(self):
        """Check if a IAM password policy exists, if not return false

        Returns:
            Account IAM password policy or False
        """
        try:
            response = Audit.IAM_CLIENT.get_account_password_policy()
            return response['PasswordPolicy']
        except Exception as e:
            if "cannot be found" in str(e):
                return False
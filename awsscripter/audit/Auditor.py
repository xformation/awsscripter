"""Implementation of a Lambda handler as a class for a specific Lambda function.
The Lambda function is deployed with handler set to MyLambdaClass.handler.
Class fields will persist across invocations for a given Lambda container,
and so are a good way to implement caching.
An instance of the class is created for each invocation, so instance fields can
be set from the input without the data persisting."""
from __future__ import print_function
import json
import logging
import sys
import time
from datetime import datetime
import boto3

from awsscripter.audit.CredReport import CredReport
from awsscripter.audit.PasswordPolicy import PasswordPolicy
from awsscripter.audit.CloudTrail import CloudTrail
from awsscripter.common.LambdaBase import LambdaBase
from awsscripter.common.connection_manager import ConnectionManager
from awsscripter.hooks import add_audit_hooks



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
        objpasswd = PasswordPolicy()
        password_policy = objpasswd.get_account_password_policy()
        obj = CloudTrail()
        reg = obj.get_regions()
        cloud_trails = obj.get_cloudtrails(reg)

        # Comment out unwanted controls
        control1 = []
        control1.append(self.control_1_1_root_use(cred_report))
        control1.append(self.control_1_2_mfa_on_password_enabled_iam(cred_report))
        control1.append(self.control_1_3_unused_credentials(cred_report))
        control1.append(self.control_1_4_rotated_keys(cred_report))
        control1.append(self.control_1_5_password_policy_uppercase(password_policy))
        control1.append(self.control_1_6_password_policy_lowercase(password_policy))
        control1.append(self.control_1_7_password_policy_symbol(password_policy))
        control1.append(self.control_1_8_password_policy_number(password_policy))
        control1.append(self.control_1_9_password_policy_length(password_policy))
        control1.append(self.control_1_10_password_policy_reuse(password_policy))
        control1.append(self.control_1_11_password_policy_expire(password_policy))
        control1.append(self.control_1_12_root_key_exists(cred_report))
        control1.append(self.control_1_13_root_mfa_enabled())
        #defining control 2
        control2 = []
        control2.append(self.control_2_1_ensure_cloud_trail_all_regions(cloud_trails))
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

    # 1.2 Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Scored)
    def control_1_2_mfa_on_password_enabled_iam(self, credreport):
        """Summary
        Args:
            credreport (TYPE): Description
        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "1.2"
        description = "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password"
        scored = True
        for i in range(len(credreport)):
            # Verify if the user have a password configured
            if credreport[i]['password_enabled'] == "true":
                # Verify if password users have MFA assigned
                if credreport[i]['mfa_active'] == "false":
                    result = False
                    failReason = "No MFA on users with password. "
                    offenders.append(str(credreport[i]['arn']))
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    # 1.3 Ensure credentials unused for 90 days or greater are disabled (Scored)
    def control_1_3_unused_credentials(slef, credreport):
        """Summary
        Args:
            credreport (TYPE): Description
        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "1.3"
        description = "Ensure credentials unused for 90 days or greater are disabled"
        scored = True
        # Get current time
        now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
        frm = "%Y-%m-%dT%H:%M:%S+00:00"

        # Look for unused credentails
        for i in range(len(credreport)):
            if credreport[i]['password_enabled'] == "true":
                try:
                    delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['password_last_used'], frm)
                    # Verify password have been used in the last 90 days
                    if delta.days > 90:
                        result = False
                        failReason = "Credentials unused > 90 days detected. "
                        offenders.append(str(credreport[i]['arn']) + ":password")
                except:
                    pass  # Never used
            if credreport[i]['access_key_1_active'] == "true":
                try:
                    delta = datetime.strptime(now, frm) - datetime.strptime(
                        credreport[i]['access_key_1_last_used_date'], frm)
                    # Verify password have been used in the last 90 days
                    if delta.days > 90:
                        result = False
                        failReason = "Credentials unused > 90 days detected. "
                        offenders.append(str(credreport[i]['arn']) + ":key1")
                except:
                    pass
            if credreport[i]['access_key_2_active'] == "true":
                try:
                    delta = datetime.strptime(now, frm) - datetime.strptime(
                        credreport[i]['access_key_2_last_used_date'], frm)
                    # Verify password have been used in the last 90 days
                    if delta.days > 90:
                        result = False
                        failReason = "Credentials unused > 90 days detected. "
                        offenders.append(str(credreport[i]['arn']) + ":key2")
                except:
                    # Never used
                    pass
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    # 1.4 Ensure access keys are rotated every 90 days or less (Scored)
    def control_1_4_rotated_keys(self, credreport):
        """Summary
        Args:
            credreport (TYPE): Description
        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "1.4"
        description = "Ensure access keys are rotated every 90 days or less"
        scored = True
        # Get current time
        now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(time.time()))
        frm = "%Y-%m-%dT%H:%M:%S+00:00"

        # Look for unused credentails
        for i in range(len(credreport)):
            if credreport[i]['access_key_1_active'] == "true":
                try:
                    delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_1_last_rotated'],
                                                                            frm)
                    # Verify keys have rotated in the last 90 days
                    if delta.days > 90:
                        result = False
                        failReason = "Key rotation >90 days or not used since rotation"
                        offenders.append(str(credreport[i]['arn']) + ":unrotated key1")
                except:
                    pass
                try:
                    last_used_datetime = datetime.strptime(credreport[i]['access_key_1_last_used_date'], frm)
                    last_rotated_datetime = datetime.strptime(credreport[i]['access_key_1_last_rotated'], frm)
                    # Verify keys have been used since rotation.
                    if last_used_datetime < last_rotated_datetime:
                        result = False
                        failReason = "Key rotation >90 days or not used since rotation"
                        offenders.append(str(credreport[i]['arn']) + ":unused key1")
                except:
                    pass
            if credreport[i]['access_key_2_active'] == "true":
                try:
                    delta = datetime.strptime(now, frm) - datetime.strptime(credreport[i]['access_key_2_last_rotated'],
                                                                            frm)
                    # Verify keys have rotated in the last 90 days
                    if delta.days > 90:
                        result = False
                        failReason = "Key rotation >90 days or not used since rotation"
                        offenders.append(str(credreport[i]['arn']) + ":unrotated key2")
                except:
                    pass
                try:
                    last_used_datetime = datetime.strptime(credreport[i]['access_key_2_last_used_date'], frm)
                    last_rotated_datetime = datetime.strptime(credreport[i]['access_key_2_last_rotated'], frm)
                    # Verify keys have been used since rotation.
                    if last_used_datetime < last_rotated_datetime:
                        result = False
                        failReason = "Key rotation >90 days or not used since rotation"
                        offenders.append(str(credreport[i]['arn']) + ":unused key2")
                except:
                    pass
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

    # 1.6 Ensure IAM password policy requires at least one lowercase letter (Scored)
    def control_1_6_password_policy_lowercase(self, passwordpolicy):
        """Summary
        Args:
            passwordpolicy (TYPE): Description
        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "1.6"
        description = "Ensure IAM password policy requires at least one lowercase letter"
        scored = True
        if passwordpolicy is False:
            result = False
            failReason = "Account does not have a IAM password policy."
        else:
            if passwordpolicy['RequireLowercaseCharacters'] is False:
                result = False
                failReason = "Password policy does not require at least one uppercase letter"
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    # 1.7 Ensure IAM password policy requires at least one symbol (Scored)
    def control_1_7_password_policy_symbol(self, passwordpolicy):
        """Summary
        Args:
            passwordpolicy (TYPE): Description
        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "1.7"
        description = "Ensure IAM password policy requires at least one symbol"
        scored = True
        if passwordpolicy is False:
            result = False
            failReason = "Account does not have a IAM password policy."
        else:
            if passwordpolicy['RequireSymbols'] is False:
                result = False
                failReason = "Password policy does not require at least one symbol"
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    # 1.8 Ensure IAM password policy requires at least one number (Scored)
    def control_1_8_password_policy_number(self, passwordpolicy):
        """Summary
        Args:
            passwordpolicy (TYPE): Description
        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "1.8"
        description = "Ensure IAM password policy requires at least one number"
        scored = True
        if passwordpolicy is False:
            result = False
            failReason = "Account does not have a IAM password policy."
        else:
            if passwordpolicy['RequireNumbers'] is False:
                result = False
                failReason = "Password policy does not require at least one number"
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    def control_1_9_password_policy_length(self, passwordpolicy):
        """Summary
        Args:
            passwordpolicy (TYPE): Description
        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "1.9"
        description = "Ensure IAM password policy requires minimum length of 14 or greater"
        scored = True
        if passwordpolicy is False:
            result = False
            failReason = "Account does not have a IAM password policy."
        else:
            if passwordpolicy['MinimumPasswordLength'] < 14:
                result = False
                failReason = "Password policy does not require at least 14 characters"
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    def control_1_10_password_policy_reuse(self, passwordpolicy):
        """Summary
        Args:
            passwordpolicy (TYPE): Description
        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "1.10"
        description = "Ensure IAM password policy prevents password reuse"
        scored = True
        if passwordpolicy is False:
            result = False
            failReason = "Account does not have a IAM password policy."
        else:
            try:
                if passwordpolicy['PasswordReusePrevention'] == 24:
                    pass
                else:
                    result = False
                    failReason = "Password policy does not prevent reusing last 24 passwords"
            except:
                result = False
                failReason = "Password policy does not prevent reusing last 24 passwords"
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    def control_1_11_password_policy_expire(self, passwordpolicy):
        """Summary
        Args:
            passwordpolicy (TYPE): Description
        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "1.11"
        description = "Ensure IAM password policy expires passwords within 90 days or less"
        scored = True
        if passwordpolicy is False:
            result = False
            failReason = "Account does not have a IAM password policy."
        else:
            if passwordpolicy['ExpirePasswords'] is True:
                if 0 < passwordpolicy['MaxPasswordAge'] > 90:
                    result = False
                    failReason = "Password policy does not expire passwords after 90 days or less"
            else:
                result = False
                failReason = "Password policy does not expire passwords after 90 days or less"
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}

    def control_1_12_root_key_exists(self, credreport):
        """Summary
        Args:
            credreport (TYPE): Description
        Returns:
            TYPE: Description
        """
        result = True
        failReason = ""
        offenders = []
        control = "1.12"
        description = "Ensure no root account access key exists"
        scored = True
        if (credreport[0]['access_key_1_active'] == "true") or (credreport[0]['access_key_2_active'] == "true"):
            result = False
            failReason = "Root have active access keys"
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}



    def control_2_1_ensure_cloud_trail_all_regions(self, cloudtrails):
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
            print(json.dumps(outer, sort_keys=True, indent=4,  separators=(',', ': ')))
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



    def DP_4_2_s3_bucket_public_read_prohibited(self):
        result = True
        failReason = ""
        offenders = []
        control = "4.2"
        description = "No Public read access for S3 Buckets"
        scored = False
        offenders = []
        s3_client = boto3.client('s3')
        buckets = s3_client.list_buckets()
        public_access = False
        for bucket in buckets['Buckets']:
            print(bucket)

        #       acl_bucket = s3_client.get_bucket_acl(Bucket=bucket['Name'])
        #       print(yaml.dump(acl_bucket))
        #       for grantee in acl_bucket['Grants']:
        #           print(grantee)
        #           if len(grantee['Grantee']) > 0:
        #                 print(grantee['Grantee'])
        #                 for uri in (grantee['Grantee'].keys()):
        #                     if uri == 'URI':
        #                         if grantee['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers':
        #                             public_access = True
        #                             print(public_access)
        #     if public_access == True:
        #         offenders.append(bucket['Name'])
        #         public_access = False
        #
        #
        # if len(offenders) > 0:
        #     result = False
        #     failReason = "There S3 Buckets available with Public Read Access"
        return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'ScoredControl': scored,
                'Description': description, 'ControlId': control}


auditor = Auditor("myname","myporject","us-east-1")
auditor.handle("test","test")
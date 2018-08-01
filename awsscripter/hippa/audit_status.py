# -*- coding: utf-8 -*-

"""
awsscripter.audit.audit_status

This module implemets structs for simplified audit status
"""


class AuditStatus(object):
    """
    StackStatus stores simplified stack statuses.
    """
    STARTED = "STARTED"
    IN_PROGRESS = "INPROGRESS"
    COMPLETE = "COMPLETE"

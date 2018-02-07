"""Base class for implementing AWS functionalities as classes.
Add additional features here common to all your AWS functionalities , like querying status."""


class AwsBase(object):
    def get_status(self):
        raise NotImplementedError
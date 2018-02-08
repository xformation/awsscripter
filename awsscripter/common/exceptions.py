# -*- coding: utf-8 -*-


class awsscripterException(Exception):
    """
    Base class for all awsscripter errors
    """
    pass


class ProjectAlreadyExistsError(awsscripterException):
    """
    Error raised when awsscripter project already exists.
    """
    pass


class InvalidawsscripterDirectoryError(awsscripterException):
    """
    Error raised if a awsscripter directory is invalid.
    """
    pass


class InvalidEnvironmentPathError(awsscripterException):
    """
    Error raised if the environment path string is invalid
    """
    pass


class ConfigItemNotFoundError(awsscripterException):
    """
    Error raised if a necessary config item has not been provided
    """
    pass


class UnsupportedTemplateFileTypeError(awsscripterException):
    """
    Error raised if an unsupported template file type is used.
    """
    pass


class TemplateawsscripterHandlerError(awsscripterException):
    """
    Error raised if awsscripter_handler() is not defined correctly in the template.
    """
    pass


class DependencyStackNotLaunchedError(awsscripterException):
    """
    Error raised when a dependency stack has not been launched
    """
    pass


class DependencyStackMissingOutputError(awsscripterException):
    """
    Error raised if a dependency stack does not have the correct outputs.
    """
    pass


class CircularDependenciesError(awsscripterException):
    """
    Error raised if there are circular dependencies
    """
    pass


class UnknownStackStatusError(awsscripterException):
    """
    Error raised if an unknown stack status is received.
    """
    pass


class UnknownAuditStatusError(awsscripterException):
    """
    Error raised if an unknown stack status is received.
    """
    pass

class RetryLimitExceededError(awsscripterException):
    """
    Error raised if the request limit is exceeded.
    """
    pass


class UnknownHookTypeError(awsscripterException):
    """
    Error raised if an unrecognised hook type is received.
    """


class VersionIncompatibleError(awsscripterException):
    """
    Error raised if configuration incompatible with running version.
    """
    pass


class ProtectedStackError(awsscripterException):
    """
    Error raised upon execution of an action under active protection
    """
    pass


class UnknownStackChangeSetStatusError(awsscripterException):
    """
    Error raised if an unknown stack change set status is received.
    """
    pass


class InvalidHookArgumentTypeError(awsscripterException):
    """
    Error raised if a hook's argument type is invalid.
    """
    pass


class InvalidHookArgumentSyntaxError(awsscripterException):
    """
    Error raised if a hook's argument syntax is invalid.
    """
    pass


class InvalidHookArgumentValueError(awsscripterException):
    """
    Error raised if a hook's argument value is invalid.
    """
    pass


class CannotUpdateFailedStackError(awsscripterException):
    """
    Error raised when a failed stack is updated.
    """
    pass


class StackDoesNotExistError(awsscripterException):
    """
    Error raised when a stack does not exist.
    """
    pass


class ConfigFileNotFoundError(awsscripterException):
    """
    Error raised when a config file does not exist.
    """
    pass


class EnvironmentNotFoundError(awsscripterException):
    """
    Error raised when a environment does not exist.
    """
    pass

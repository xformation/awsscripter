import click

from awsscripter.stack.helpers import catch_exceptions, confirmation
from awsscripter.stack.helpers import get_stack_or_env
from awsscripter.stack.stack_status import StackStatus


@click.command(name="create")
@click.argument("path")
@click.argument("change-set-name", required=False)
@click.option(
    "-y", "--yes", is_flag=True, help="Assume yes to all questions."
)
@click.pass_context
@catch_exceptions
def create_command(ctx, path, change_set_name, yes):
    """
    Creates a stack or a change set.

    Creates a stack for a given config PATH. Or if CHANGE_SET_NAME is specified
    creates a change set for stack in PATH.
    """
    action = "create"

    stack, _ = get_stack_or_env(ctx, path)
    if change_set_name:
        confirmation(action, yes, change_set=change_set_name, stack=path)
        stack.create_change_set(change_set_name)
    else:
        confirmation(action, yes, stack=path)
        response = stack.create()
        if response != StackStatus.COMPLETE:
            exit(1)

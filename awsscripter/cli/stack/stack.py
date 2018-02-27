import click

from awsscripter.cli.stack.create import create_command
from awsscripter.cli.stack.delete import delete_command
from awsscripter.cli.stack.describe import describe_group
from awsscripter.cli.stack.execute import execute_command
from awsscripter.cli.stack.launch import launch_command
from awsscripter.cli.stack.list import list_group
from awsscripter.cli.stack.policy import set_policy_command
from awsscripter.cli.stack.status import status_command
from awsscripter.cli.stack.template import validate_command, generate_command
from awsscripter.cli.stack.update import update_command


@click.group(name="stack")
def stack_group():
    """
    Commands for auditing aws environment with awsscripter.

    """
    pass


stack_group.add_command(create_command)
stack_group.add_command(delete_command)
stack_group.add_command(describe_group)
stack_group.add_command(execute_command)
stack_group.add_command(update_command)
stack_group.command(delete_command)
stack_group.command(launch_command)
stack_group.command(execute_command)
stack_group.command(validate_command)
stack_group.add_command(generate_command)
stack_group.add_command(set_policy_command)
stack_group.add_command(status_command)
stack_group.add_command(list_group)
stack_group.add_command(describe_group)

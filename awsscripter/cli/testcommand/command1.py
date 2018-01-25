import click

from awsscripter.stack.helpers import catch_exceptions, confirmation

@click.command(name="command1")
@click.argument("command1_arg")
@click.pass_context
@catch_exceptions
def testcommand_command1(ctx, command1_arg):
    """
    Sample test command1
    """
    print("Running testcommand1 with argument  " + command1_arg)

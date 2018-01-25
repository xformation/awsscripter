import click

from awsscripter.stack.helpers import catch_exceptions, confirmation

@click.command(name="command2")
@click.argument("command2_arg")
@click.pass_context
@catch_exceptions
def testcommand_command2(ctx, command2_arg):
    """
    Sample test command2
    """
    print("Running testcommand2 with argument  " + command2_arg)

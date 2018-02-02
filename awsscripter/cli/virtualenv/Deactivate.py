import click
from awsscripter.stack.helpers import catch_exceptions, confirmation

@click.command(name="Deactivate")
@click.argument("deactivate_arg")
@click.pass_context
@catch_exceptions
def virtualenv_deactivate(ctx, deactivate_arg):
    """
    Command to Activate venv
    """
    #deactivate_arg = "deactivate"
    print("Use command to Activate virtual environment " + deactivate_arg)
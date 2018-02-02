import click
from awsscripter.stack.helpers import catch_exceptions, confirmation

@click.command(name="Activate")
@click.argument("activate_arg")
@click.pass_context
@catch_exceptions
def virtualenv_activate(ctx, activate_arg):
    """
    Command to Activate venv
    """
    #activate_arg="source venv/bin/activate"
    print("Use command to Activate virtual environment " + activate_arg)
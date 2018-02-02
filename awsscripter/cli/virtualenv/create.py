import click
from awsscripter.stack.helpers import catch_exceptions, confirmation

@click.command(name="create")
@click.argument("create_arg")
@click.pass_context
@catch_exceptions
def virtualenv_create(ctx, create_arg):
    """
    Command to create venv
    """
    #create_arg = "virtualenv venv"
    print("Use command to run virtual environment " + create_arg)
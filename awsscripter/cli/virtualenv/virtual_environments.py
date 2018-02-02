import click
from awsscripter.cli.virtualenv.create import virtualenv_create
from awsscripter.cli.virtualenv.Activate import virtualenv_activate
from awsscripter.cli.virtualenv.Deactivate import virtualenv_deactivate

@click.group(name="Virtualenv")
def virtualenv_group():
    """
    Commands for virtual environments

    """
    pass
virtualenv_group.add_command(virtualenv_create)
virtualenv_group.add_command(virtualenv_activate)
virtualenv_group.add_command(virtualenv_deactivate)

import click

from awsscripter.stack.helpers import catch_exceptions, confirmation

@click.command(name="HIPPA")
@click.argument("level")
@click.pass_context
@catch_exceptions
def audit_hippa_command(ctx, level):
    """
    Depending on level , it will perform the CISP audit, by default the level is FULL
    """
    print("Auditing with level  " + level)

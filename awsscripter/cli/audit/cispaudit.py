import click

from awsscripter.stack.helpers import catch_exceptions, confirmation
from awsscripter.audit.Auditor import Auditor
@click.command(name="CISP")
@click.argument("level")
@click.pass_context
@catch_exceptions
def audit_cisp_command(ctx, level):
    """
    Depending on level , it will perform the CISP audit, by default the level is FULL
    """
    print("Auditing with level  " + level)
    auditor = Auditor("myname", "myproject", "us-east-1")
    auditor.handle("test", "test")


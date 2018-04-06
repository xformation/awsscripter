import click
from awsscripter.stack.helpers import catch_exceptions, confirmation
from awsscripter.audit.Auditor import Auditor
import logging
@click.command(name="CISP")
@click.option(
    "--level", type=click.Choice(["FULL", "LESS"]), default="FULL",
    help="The level of audit , default is full")
@click.pass_context
@catch_exceptions
def audit_cisp_command(ctx, level):
    """
    Depending on level , it will perform the CISP audit, by default the level is FULL
    """
    logger = logging.getLogger(__name__)
    logger.info("Auditing with level  " + level)
    auditor = Auditor("myname", "myproject", "us-east-1")
    auditor.ha("test", "test")


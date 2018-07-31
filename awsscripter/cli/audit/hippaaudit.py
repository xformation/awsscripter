import click
import logging

from awsscripter.stack.helpers import catch_exceptions, confirmation
from awsscripter.hippa.HippaAuditor import HippaAuditor


@click.command(name="HIPPA")
# @click.argument("level")
@click.option(
    "--level", type=click.Choice(["FULL", "LESS"]), default="FULL",
    help="The level of audit , default is full")
@click.pass_context
@catch_exceptions
def audit_hippa_command(ctx, level):
    """
    Depending on level , it will perform the CISP audit, by default the level is FULL
    """
    print("Auditing with level  " + level)

    logger = logging.getLogger(__name__)
    logger.info("Auditing with level  " + level)
    # auditor = HippaAuditor("myname", "myproject", "us-east-1")
    # auditor.handle("test", "test")

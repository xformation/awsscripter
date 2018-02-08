import click
from awsscripter.stack.helpers import catch_exceptions, confirmation
from awsscripter.audit.Auditor import Auditor
import logging
@click.command(name="CPU")
@click.option(
    "--level", type=click.Choice(["FULL", "LESS"]), default="FULL",
    help="The level of audit , default is full")
@click.pass_context
@catch_exceptions
def monitoring_cpu_command(ctx, level):
    """
    Depending on level , it will perform the CISP audit, by default the level is FULL
    """
    logger = logging.getLogger(__name__)
    logger.info("Monitoring CPU")


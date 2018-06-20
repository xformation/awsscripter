import click
from awsscripter.stack.helpers import catch_exceptions, confirmation
from awsscripter.billing.hourlybilltoes import billtoes
from awsscripter.audit.Auditor import Auditor
import logging
@click.command(name="hourlybilling")
@click.option(
    "--level", type=click.Choice(["FULL", "LESS"]), default="FULL",
    help="The level of audit , default is full")
@click.pass_context
@catch_exceptions
def hbrtoes_command(ctx, level):
    """
    Depending on level , it will perform the Billing audit, by default the level is FULL
    """
    logger = logging.getLogger(__name__)
    logger.info("Hourly Billing Report" + level)
    biller = billtoes()
    biller.main()
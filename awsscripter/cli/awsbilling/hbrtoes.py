import click
from awsscripter.stack.helpers import catch_exceptions, confirmation
from awsscripter.billing.hourlybilltoes import Billtoes

import logging
@click.command(name="hourlybilling")
@click.option(
    "--level", type=click.Choice(["FULL", "LESS"]), default="FULL",
    help="The level of audit , default is full")
@click.option("--path",prompt="Enter report name with absolute path",help="Enter file path")
@click.pass_context
@catch_exceptions
def hbrtoes_command(ctx, level,path):
    """
    Depending on level , it will perform the Billing audit, by default the level is FULL
    """
    logger = logging.getLogger(__name__)
    logger.info("Hourly Billing Report" + level)
    biller = Billtoes()
    biller.starter(path)
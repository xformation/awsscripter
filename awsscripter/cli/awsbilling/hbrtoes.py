import click
from awsscripter.stack.helpers import catch_exceptions, confirmation
from awsscripter.billing.hourlybilltoes import Billtoes

import logging
@click.command(name="hourlybilling")
@click.option(
    "--level", type=click.Choice(["FULL", "LESS"]), default="FULL",
    help="The level of audit , default is full")
@click.option("--path",prompt="Enter report name with absolute path",help="Enter file path")
@click.option("--hostip",prompt="ES IP")
@click.option("--port",prompt="ES port number")
@click.option("--index",prompt="Index name")
@click.pass_context
@catch_exceptions
def hbrtoes_command(ctx, level,path,hostip,port,index):
    """
    Depending on level , it will perform the Billing audit, by default the level is FULL
    """
    logger = logging.getLogger(__name__)
    logger.info("Hourly Billing Report" + level)
    esurl=str("http://"+str(hostip)+":"+str(port))
    print(esurl)
    biller = Billtoes(path,esurl,index)
    biller.starter()
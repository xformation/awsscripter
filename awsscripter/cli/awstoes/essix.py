import subprocess
from awsscripter.aws_config_to_es import esingest
import click
# import os.system
# import os.spawnl
from awsscripter.stack.helpers import catch_exceptions, confirmation
# from awsscripter.audit.Auditor import Auditor
import logging
@click.command(name="awstoes")
@click.option(
    "--level", type=click.Choice(["FULL", "LESS"]), default="FULL",
    help="The level of audit , default is full")
@click.pass_context
@catch_exceptions

def es_command(ctx, level):
    """
    AWS config snapshot will be uploaded to ElasticSearch
    """
    logger = logging.getLogger(__name__)
    logger.info("Auditing with level  " + level)
    # auditor = Auditor("myname", "myproject", "us-east-1")
    # auditor.handle("test", "test")
    subprocess.Popen("python D:\\mycode\\awsscripter\\awsscripter\\aws_config_to_es\\esingest.py", shell=True)
    exit()

import subprocess
from awsscripter.aws_config_to_es import esingest
from awsscripter.aws_config_to_es import elastic
from argparse import ArgumentParser
import click
# import os.system
# import os.spawnl
from awsscripter.stack.helpers import catch_exceptions, confirmation
# from awsscripter.audit.Auditor import Auditor
import logging
@click.command(name="awstoes")
@click.option(
    "--level", type=click.Choice(["FULL", "LESS"]), default="FULL",
    help="This will upload aws config to ElasticSearch 6")
@click.pass_context
@catch_exceptions
# # @click.option("--path",prompt="Enter report name with absolute path",help="Enter file path")
# @click.option("--destination",default="localhost:9200")
# @click.option("--region",default ="us-east-1")
# @click.option("--verbose",default = False)


def es_command(ctx, level):
    """
    AWS config snapshot will be uploaded to ElasticSearch
    """
    logger = logging.getLogger(__name__)
    logger.info("Auditing with level  " + level)

    # auditor = Auditor("myname", "myproject", "us-east-1")
    # auditor.handle("test", "test")
    # parser = ArgumentParser()
    # parser.add_argument('--region', '-r',default='us-east-1',
    #                     help='The region that needs to be analyzed. If left '
    #                          'blank all regions will be analyzed.')
    # parser.add_argument('--destination', '-d', default='localhost:9200',
    #                         help='The ip:port of the elastic search instance')
    # parser.add_argument('--verbose', '-v', action='store_true', default=False,
    #                     help='If selected, the app runs in verbose mode '
    #                          '--
    # args = parser.parse_args()
    verbose_log = logging.getLogger("verbose")
    verbose_log.setLevel(level=logging.FATAL)
    ingest = esingest.Esingest()
    destination = 'http://localhost:9200'
    es = elastic.ElasticSearch(connections=destination, log=verbose_log)
    ingest.main(es )
    # subprocess.Popen("python D:\\mycode\\awsscripter\\awsscripter\\aws_config_to_es\\esingest.py", shell=True)
    # exit() #had added these two line for direct code execution

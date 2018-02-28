import click
from awsscripter.cli.list.ec2 import list_ec2


@click.group(name="list")
def list_group():
    """
    packet security check
    :return:
    """
    pass
list_group.add_command(list_ec2)

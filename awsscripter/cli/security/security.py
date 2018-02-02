import click
from awsscripter.cli.security.tcp import security_tcp
from awsscripter.cli.security.udp import security_udp

@click.group(name="security")
def security_group():
    """
    packet security check
    :return:
    """
    pass
security_group.add_command(security_tcp)
security_group.add_command(security_udp)
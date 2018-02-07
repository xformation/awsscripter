import click
from awsscripter.cli.testcode.tcp import password_tcp
from awsscripter.cli.testcode.udp import password_udp
@click.group(name="password")
def password_group():
    #it contains command1 and command2
    print("gropuresult")

    pass



password_group.add_command(password_tcp)
password_group.add_command(password_udp)
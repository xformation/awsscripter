import click
from awsscripter.cli.testcommand.command1 import testcommand_command1
from awsscripter.cli.testcommand.command2 import testcommand_command2

@click.group(name="testcommand")
def testcommand_group():
    """
    A sample testcommand

    """
    pass
testcommand_group.add_command(testcommand_command1)
testcommand_group.add_command(testcommand_command2)
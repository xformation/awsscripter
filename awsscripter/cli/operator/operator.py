import click
from awsscripter.cli.operator.addition import addition
from awsscripter.cli.operator.subtraction import subtraction


@click.group(name="operator")
def operator_group():
    """
    this is an operator

    """

pass



operator_group.add_command(addition)
operator_group.add_command(subtraction)
import click

from awsscripter.cli.monitoring.cpu import monitoring_cpu_command
@click.group(name="monitor", chain=True)
@click.pass_context
def monitoring_group(ctx):
    """
    Commands for auditing aws environment with awsscripter. This will iclude CISP/ HIPPA Audit for now.

    """
    pass
monitoring_group.add_command(monitoring_cpu_command)

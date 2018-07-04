import click

from awsscripter.cli.awsbilling.hbrtoes import hbrtoes_command
from awsscripter.cli.audit.hippaaudit import audit_hippa_command
from awsscripter.cli.audit.pcidss import audit_pcidss_command
@click.group(name="billing", chain=True)
@click.pass_context
def billing_group(ctx):
    """
    Commands for monitoring Billing aws environment with awsscripter.

    """
    pass
billing_group.add_command(hbrtoes_command)
# audit_group.add_command(audit_cisp_command)
# audit_group.add_command(audit_hippa_command)
# audit_group.add_command(audit_pcidss_command)
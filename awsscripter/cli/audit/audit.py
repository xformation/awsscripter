import click

from awsscripter.cli.audit.cispaudit import audit_cisp_command
from awsscripter.cli.audit.hippaaudit import audit_hippa_command
from awsscripter.cli.audit.pcidss import audit_pcidss_command
@click.group(name="audit", chain=True)
@click.pass_context
def audit_group(ctx):
    """
    Commands for auditing aws environment with awsscripter. This will iclude CISP/ HIPPA Audit for now.

    """
    pass
audit_group.add_command(audit_cisp_command)
audit_group.add_command(audit_hippa_command)
audit_group.add_command(audit_pcidss_command)

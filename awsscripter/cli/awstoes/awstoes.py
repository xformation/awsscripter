import click

# from awsscripter.cli.audit.cispaudit import audit_cisp_command
# from awsscripter.cli.audit.hippaaudit import audit_hippa_command
# from awsscripter.cli.audit.pcidss import audit_pcidss_command
from awsscripter.cli.awstoes.essix import es_command
@click.group(name="es", chain=True)
@click.pass_context
def es_group(ctx):
    """
    Commands for uploading config snapshot to ElasticSearch Server provided by user.

    """
    pass
# audit_group.add_command(audit_cisp_command)
# audit_group.add_command(audit_hippa_command)
# audit_group.add_command(audit_pcidss_command)
es_group.add_command(es_command)
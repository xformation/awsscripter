import click

from awsscripter.stack.helpers import catch_exceptions


@click.group(name="audit")
def audit_group():
    """
    Commands for auditing aws environment with awsscripter. This will iclude CISP/ HIPPA Audit for now.

    """
    pass

@audit_group.command("CISP")
@click.argument('level')
# @click.Choice('Full', 'Medium')
@catch_exceptions
@click.pass_context
def audit_cisp(ctx, level):
    """
    Depending on level , it will perform the CISP audit, by default the level is FULL
    """
    print("Auditing with level  " + level)


@audit_group.command("HIPPA")
@catch_exceptions
@click.argument('level')
# @click.Choice('Full', 'Medium')
@click.pass_context
def audit_hippa(ctx, level):
    """
    Depending on level , it will perform the HIPPA audit, by default the level is FULL
    """
    print("Auditing with level  " + level)

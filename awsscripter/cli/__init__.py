# -*- coding: utf-8 -*-

"""
awsscripter.cli

This module implements awsscripter's CLI, and should not be directly imported.
"""

import os
import warnings

import click
import colorama
import yaml
from awsscripter.cli.init.init import init_group
from awsscripter.cli.audit.audit import audit_group
from awsscripter.cli.stack.stack import stack_group
from awsscripter.cli.testcommand.testcommand import testcommand_group
from awsscripter.stack.helpers import  setup_logging, catch_exceptions
from awsscripter import __version__
from awsscripter.cli.security.security import security_group
from awsscripter.cli.ex.test1 import cli_com
from awsscripter.cli.ex.test2 import group_method


@click.group()
@click.version_option(version=__version__, prog_name="awsscripter")
@click.option("--debug", is_flag=True, help="Turn on debug logging.")
@click.option("--dir", "directory", help="Specify awsscripter directory.")
@click.option(
    "--output", type=click.Choice(["yaml", "json"]), default="yaml",
    help="The formatting style for command output.")
@click.option("--no-colour", is_flag=True, help="Turn off output colouring.")
@click.option(
    "--var", multiple=True, help="A variable to template into config files.")
@click.option(
    "--var-file", multiple=True, type=click.File("rb"),
    help="A YAML file of variables to template into config files.")
@click.pass_context
@catch_exceptions
def cli(
        ctx, debug, directory, no_colour, output, var, var_file
):
    """
    awsscripter is a tool to manage your cloud native infrastructure deployments.

    """
    logger = setup_logging(debug, no_colour)
    colorama.init()
    # Enable deprecation warnings
    warnings.simplefilter("always", DeprecationWarning)
    ctx.obj = {
        "user_variables": {},
        "output_format": output,
        "no_colour": no_colour,
        "awsscripter_dir": directory if directory else os.getcwd()
    }
    if var_file:
        for fh in var_file:
            parsed = yaml.safe_load(fh.read())
            ctx.obj["user_variables"].update(parsed)

            # the rest of this block is for debug purposes only
            existing_keys = set(ctx.obj["user_variables"].keys())
            new_keys = set(parsed.keys())
            overloaded_keys = existing_keys & new_keys  # intersection
            if overloaded_keys:
                logger.debug(
                    "Duplicate variables encountered: {0}. "
                    "Using values from: {1}."
                    .format(", ".join(overloaded_keys), fh.name)
                )

    if var:
        # --var options overwrite --var-file options
        for variable in var:
            variable_key, variable_value = variable.split("=")
            if variable_key in ctx.obj["user_variables"]:
                logger.debug(
                    "Duplicate variable encountered: {0}. "
                    "Using value from --var option."
                    .format(variable_key)
                )
            ctx.obj["user_variables"].update({variable_key: variable_value})


cli.add_command(init_group)
cli.add_command(audit_group)
cli.add_command(stack_group)
cli.add_command(testcommand_group)
cli.add_command(security_group)
cli.add_command(cli_com)
cli.add_command(group_method)
import click


@click.group(name="cli_com", chain=True)
def cli_com():
    """
    group command with chain
     :return:
    """




    pass


@cli_com.command('command1')
def command1():
    click.echo('command1 called')


@cli_com.command('command2')
def command2():
    click.echo('command2 called')
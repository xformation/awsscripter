import click

@click.command()
@click.option("--setting", help= "this is setting")


def setting(setting):
    print("this is the setting environment of cli", setting)

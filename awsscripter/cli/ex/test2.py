import click


@click.group(name="group_method", chain=True)
def group_method():
    """ math functions"""
    pass


@group_method.command('add')
def add():
    a=input("enter a value ")
    b=input("enter b value ")
    c=a+b
    click.echo(c)


@group_method.command('sub')
def sub():
    a = input("enter a value ")
    b = input("enter b value ")
    c = a - b
    click.echo(c)


@group_method.command('mul')
def mul():
    a = input("enter a value ")
    b = input("enter b value ")
    c = a * b
    click.echo(c)


@group_method.command('div')
def div():
    a = input("enter a value ")
    b = input("enter b value ")
    c = a / b
    click.echo(c)


@group_method.command('name')
def name():
    a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    print(a[-8], a[-2], a[13], a[4], a[2], a[-7], a[8], a[10],a[-8])
import click


@click.command(name="mul")
@click.option('--count', type=click.IntRange(0, 20, clamp=True))
@click.option('--digit', type=click.IntRange(0, 10))
def mul(count, digit):
    click.echo(int(digit) * count)


if __name__ == '__main__':
    mul()





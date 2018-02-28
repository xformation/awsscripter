import click
from awsscripter.common.connection_manager import ConnectionManager
import logging

@click.command(name="ec2")
def list_ec2():
    print ("listing all ec2 machines in all regions")
    connection_manager = ConnectionManager('us-east-1', iam_role=None)
    list_ec2_kwargs = {
    }
    response = connection_manager.call(
        service="ec2",
        command="describe_regions",
        kwargs=list_ec2_kwargs
    )
    logger = logging.getLogger(__name__)
    logger.info(
        "Generated credential report response: %s", response['Regions']
    )
    ec2_regions = [region['RegionName'] for region in response['Regions']]
    for region in ec2_regions:
        connection_manager = ConnectionManager('us-east-1', iam_role=None)
        instances = connection_manager.call(
        service="ec2",
        command="describe_instances",
        kwargs=list_ec2_kwargs
        )
        for instance in instances:
            if instance.state["Name"] == "running":
                print(instance.id, instance.instance_type, region)


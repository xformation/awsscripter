# import boto3
#
# client = boto3.client('ec2')
# response = client.describe_instances()
#
# print

# control instance name like db (and type or diff vendors) should check vol should be
# encrypted
from collections import defaultdict

import boto3

"""
A tool for retrieving basic information from the running EC2 instances.
"""

# Connect to EC2
ec2 = boto3.resource('ec2')
client = boto3.client('ec2')

# Get information for all running instances
running_instances = ec2.instances.filter(Filters=[{
    'Name': 'instance-state-name',
    'Values': ['running']}])
# running_instances = ec2.instances.all()
ec2info = defaultdict()
for instance in running_instances:
    for tag in instance.tags:  # extracting instance name
        # print(tag)
        if 'Name'in tag['Key']:
            name = tag['Value']
            instance_id = instance.instance_id
            # Getting volumes for each instance
            blkdmapping = instance.block_device_mappings
    if 'um' in name or 'ECS' in name or 'db' in name or 'database' in name or 'sql' in name or 'couchbase' 'raik' in name or 'hbase' in name or 'oracle' in name or 'hana' in name or 'hana' in name or 'postgres' in name or 'cassandra' in name or 'hdoop' in name or 'mongo' in name or 'graph' in name or 'Neo4j' in name:
        print(instance_id)
        for volumes in blkdmapping:
            response = client.describe_volumes(VolumeIds=[volumes['Ebs']['VolumeId']])
            for i in response['Volumes']:
                print(volumes['Ebs']['VolumeId'],i['Encrypted'])

# Add instance info to a dictionary
#     ec2info[instance.id] = {
#         'Name': name,
#         'Type': instance.instance_type,
#         'State': instance.state['Name'],
#         'Private IP': instance.private_ip_address,
#         'Public IP': instance.public_ip_address,
#         'Launch Time': instance.launch_time
#         }
#
# attributes = ['Name', 'Type', 'State', 'Private IP', 'Public IP', 'Launch Time']
# for instance_id, instance in ec2info.items():
#     for key in attributes:
#         print("{0}: {1}".format(key, instance[key]))
#     print("------")



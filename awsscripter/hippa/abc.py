import boto3
import yaml

client = boto3.client('rds')
response = client.describe_db_instances()
# print(yaml.dump(response))
for dbinstances in response['DBInstances']:
    # print(dbinstances.keys())
    for db in dbinstances['DBSubnetGroup']:
        print(db['DBSubnetGroupName'])

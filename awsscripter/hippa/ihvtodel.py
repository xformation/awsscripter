# Running volumes id listing program
# import boto3
# ec2 = boto3.resource('ec2', region_name='us-east-1')
# volumes = ec2.volumes.all()
# # print(volumes)
# for volume in volumes:
#     print(volume)

import boto3
import yaml
import json
# client = boto3.client('ec2')
# response = client.describe_instances(InstanceIds=['i-09eaf0768ac8c16eb']) # i need to check if we can pass instacne name here directly
# # print(response['Reservations'])
# for itms in response['Reservations']:
#     # print(itms['Instances'])
#     for inst in itms['Instances']:
#         print((inst))
    # break

#Program for checking encription on praticular volume
import datetime
import time
# client = boto3.client('ec2')
# response = client.describe_volumes(VolumeIds=['vol-03db60b4d26b4616b'])
# # print(response['Volumes'])
# for i in response['Volumes']:
#     print(i['Encrypted'])



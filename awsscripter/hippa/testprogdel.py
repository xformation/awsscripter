import boto3
import json
client = boto3.client('dynamodb')
resonse = client.list_tables()
print(resonse)
for table in resonse['TableNames']:
    print(table)
    tabdescribe=client.describe_table(TableName=table)
print(tabdescribe)

if 'SSEDescription' in resonse.keys():
    print("found key")

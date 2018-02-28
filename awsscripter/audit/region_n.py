import boto3


class region_n():

    def get_regions(self):
        client = boto3.client('ec2')
        region_response = client.describe_regions()
        regions = [region['RegionName'] for region in region_response['Regions']]
        return regions
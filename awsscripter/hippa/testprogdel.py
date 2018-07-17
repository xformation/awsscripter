import boto3
import json
import yaml
# client = boto3.client('elb')
# resonse = client.describe_load_balancer_policies(LoadBalancerName='appcluster-dev-alb',PolicyNames=['appcluster-dev-alb'])
# # print(yaml.dump(resonse))
# # print(resonse['PolicyDescriptions'])
# for polname in resonse['PolicyDescriptions']:
#     print(polname)#['PolicyName'])
#
client = boto3.client('elbv2')
resonse = client.describe_load_balancers()
# print(yaml.dump(resonse))
poldata = []
i =0
for applb in resonse['LoadBalancers']:
    # print(applb['LoadBalancerName'])
# polresponse= client.describe_ssl_policies()
# print(yaml.dump(polresponse))

    polresponse= client.describe_listeners(LoadBalancerArn=applb['LoadBalancerArn'])
    # print((polresponse))
    for lispolicy in polresponse['Listeners']:
        try:
            print((lispolicy['SslPolicy']))
            poldata = lispolicy['SslPolicy']
            # print(poldata[i])
            # i += 1
        except Exception:
            pass

print(poldata)
fullpolicy = client.describe_ssl_policies(Names=['ELBSecurityPolicy-2016-08'])
print(yaml.dump(fullpolicy))
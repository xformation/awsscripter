import boto3

cloudtrail_client = boto3.client("cloudtrail")

eval = {}
eval["Configuration"] = cloudtrail_client.describe_trails()['trailList']
print(eval)

if len(eval['Configuration']) == 0:
    result = "NON_COMPLIANT"
    failreason = "No Trail Is Configured"
    print(failreason)
else:
    result = "NON_COMPLIANT"
    failreason = "Trail Is Configured"
    print(failreason)

for trail in eval['Configuration']:
    AWS_CLOUDTRAIL_NAME = trail["Name"]
    print(AWS_CLOUDTRAIL_NAME)
    result = "NON_COMPLIANT"
    failreason = "No Trail Named"
    print(failreason)
else:
        result = "NON_COMPLIANT"
        failreason = "Trail Named"
        print(failreason)

correct_trail_status = cloudtrail_client.get_trail_status(Name=AWS_CLOUDTRAIL_NAME)
if correct_trail_status['IsLogging'] != True:
    response = {"ComplianceType": "NON_COMPLIANT",
                "Annotation": "The Trail named " + AWS_CLOUDTRAIL_NAME + " is not enabled."}
print(correct_trail_status)


correct_trail = cloudtrail_client.describe_trails(trailNameList=[AWS_CLOUDTRAIL_NAME])['trailList'][0]
print(correct_trail)

correct_trail_selector = cloudtrail_client.get_event_selectors(TrailName=AWS_CLOUDTRAIL_NAME)['EventSelectors'][0]
print(correct_trail_selector)

if len(correct_trail_selector['DataResources']) != "{'Type': 'AWS::S3::Object', 'Values': ['arn:aws:s3']}":
    print("The Trail named " + AWS_CLOUDTRAIL_NAME + " do not log ALL S3 Data Events.")

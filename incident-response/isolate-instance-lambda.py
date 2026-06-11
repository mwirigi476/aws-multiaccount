import boto3, json, logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client('ec2', region_name='us-east-1')
s3  = boto3.client('s3',  region_name='us-east-1')

QUARANTINE_SG = 'sg-quarantine'
AUDIT_BUCKET  = 'fintech-encrypted-data-803871049728'

def lambda_handler(event, context):
    finding      = event.get('detail', {})
    instance_id  = finding.get('resource', {}).get('instanceDetails', {}).get('instanceId')
    finding_type = finding.get('type', 'Unknown')
    severity     = finding.get('severity', 0)
    finding_id   = finding.get('id', 'unknown')

    if not instance_id:
        logger.warning("No instance ID in finding — skipping")
        return {"status": "skipped", "reason": "no_instance_id"}

    # Get or create quarantine security group
    sg_resp = ec2.describe_security_groups(
        Filters=[{'Name': 'group-name', 'Values': [QUARANTINE_SG]}])

    if sg_resp['SecurityGroups']:
        qsg_id = sg_resp['SecurityGroups'][0]['GroupId']
    else:
        vpc_resp = ec2.describe_instances(InstanceIds=[instance_id])
        vpc_id   = vpc_resp['Reservations'][0]['Instances'][0]['VpcId']
        qsg_id   = ec2.create_security_group(
            GroupName=QUARANTINE_SG,
            Description='Quarantine SG - blocks all traffic',
            VpcId=vpc_id)['GroupId']

    # Isolate: move to quarantine SG
    ec2.modify_instance_attribute(
        InstanceId=instance_id, Groups=[qsg_id])

    # Tag as isolated
    ec2.create_tags(Resources=[instance_id], Tags=[
        {'Key': 'SecurityStatus',  'Value': 'ISOLATED'},
        {'Key': 'IsolationReason', 'Value': finding_type},
        {'Key': 'IsolationTime',   'Value': datetime.utcnow().isoformat()}
    ])

    # Write audit record to S3
    s3.put_object(
        Bucket=AUDIT_BUCKET,
        Key=f"incident-response/isolation-{finding_id}.json",
        Body=json.dumps({
            "timestamp":    datetime.utcnow().isoformat(),
            "action":       "EC2_ISOLATED",
            "instance_id":  instance_id,
            "finding_type": finding_type,
            "severity":     severity,
            "finding_id":   finding_id
        }),
        ServerSideEncryption='aws:kms'
    )

    logger.info(f"Instance {instance_id} isolated successfully")
    return {
        "status":      "isolated",
        "instance_id": instance_id,
        "severity":    severity,
        "findingType": finding_type
    }

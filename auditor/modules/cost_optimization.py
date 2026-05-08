import logging
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from botocore.exceptions import ClientError

from auditor.utils.aws_utils import call_with_backoff

logger = logging.getLogger(__name__)
central = ZoneInfo("America/Chicago")

def audit_high_cost_services(session, account_id):
    findings = []
    try:
        ce_client = session.client('ce', region_name='us-east-1')
        end_date = datetime.now(ZoneInfo("UTC")).date()
        start_date = end_date - timedelta(days=30)

        # Service-specific cost thresholds
        service_thresholds = {
            "Amazon EC2": 500,
            "Amazon RDS": 300,
            "Amazon S3": 200,
            "AWS Lambda": 100
        }

        response = call_with_backoff(
            ce_client, 'get_cost_and_usage',
            TimePeriod={'Start': start_date.strftime('%Y-%m-%d'), 'End': end_date.strftime('%Y-%m-%d')},
            Granularity='MONTHLY',
            Metrics=['UnblendedCost'],
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
        )

        for result in response['ResultsByTime']:
            for group in result.get('Groups', []):
                service = group['Keys'][0]
                cost = float(group['Metrics']['UnblendedCost']['Amount'])
                threshold = service_thresholds.get(service, 1000)
                if cost > threshold:
                    findings.append({
                        "AccountId": account_id,
                        "Region": "global",
                        "Service": "CostExplorer",
                        "Check": "High Service Cost",
                        "Status": "WARNING",
                        "FindingType": "Cost",
                        "Severity": "High",
                        "Details": f"Service {service} cost ${cost:.2f} exceeds threshold ${threshold:.2f} in period {result['TimePeriod']['Start']}.",
                        "Recommendation": f"Review {service} usage in AWS Cost Explorer and optimize resources.",
                        "Timestamp": datetime.now(central).isoformat(),
                        "Compliance": {"AWS-Well-Architected": "COST-01"}
                    })

    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "CostExplorer",
            "Check": "Cost Retrieval",
            "Status": "ERROR",
            "FindingType": "Error",
            "Severity": "Low",
            "Details": f"Error retrieving cost data: {str(e)}",
            "Recommendation": "Verify permissions for ce:GetCostAndUsage.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_idle_ec2_instances(session, account_id, regions):
    findings = []
    try:
        end_time = datetime.now(ZoneInfo("UTC"))
        start_time = end_time - timedelta(days=7)

        for region in regions:
            ec2_client = session.client('ec2', region_name=region)
            cw_client = session.client('cloudwatch', region_name=region)

            paginator = ec2_client.get_paginator('describe_instances')
            for page in paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]):
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        instance_id = instance['InstanceId']
                        try:
                            response = call_with_backoff(
                                cw_client, 'get_metric_statistics',
                                Namespace='AWS/EC2',
                                MetricName='CPUUtilization',
                                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                                StartTime=start_time,
                                EndTime=end_time,
                                Period=86400,
                                Statistics=['Average']
                            )
                            datapoints = response.get('Datapoints', [])
                            if datapoints and all(dp['Average'] < 5 for dp in datapoints):
                                findings.append({
                                    "AccountId": account_id,
                                    "Region": region,
                                    "Service": "EC2",
                                    "Check": "Idle EC2 Instance",
                                    "Status": "WARNING",
                                    "FindingType": "Cost",
                                    "Severity": "Medium",
                                    "Details": f"EC2 instance {instance_id} has average CPU utilization < 5% over 7 days.",
                                    "Recommendation": f"Consider stopping or terminating instance {instance_id}.",
                                    "Timestamp": datetime.now(central).isoformat(),
                                    "Compliance": {"AWS-Well-Architected": "COST-02"}
                                })
                        except ClientError as e:
                            findings.append({
                                "AccountId": account_id,
                                "Region": region,
                                "Service": "EC2",
                                "Check": "EC2 Metrics",
                                "Status": "ERROR",
                                "FindingType": "Error",
                                "Severity": "Low",
                                "Details": f"Error retrieving metrics for {instance_id}: {str(e)}",
                                "Recommendation": "Verify permissions for cloudwatch:GetMetricStatistics.",
                                "Timestamp": datetime.now(central).isoformat(),
                                "Compliance": {}
                            })
    except Exception as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "EC2",
            "Check": "Idle EC2 Audit",
            "Status": "ERROR",
            "FindingType": "Error",
            "Severity": "Low",
            "Details": f"Error auditing EC2 instances: {str(e)}",
            "Recommendation": "Review logs and verify EC2 audit configuration.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_unattached_ebs_volumes(session, account_id, regions):
    findings = []
    try:
        for region in regions:
            ec2_client = session.client('ec2', region_name=region)
            paginator = ec2_client.get_paginator('describe_volumes')
            for page in paginator.paginate(Filters=[{'Name': 'status', 'Values': ['available']}]):
                for volume in page.get('Volumes', []):
                    volume_id = volume['VolumeId']
                    findings.append({
                        "AccountId": account_id,
                        "Region": region,
                        "Service": "EBS",
                        "Check": "Unattached EBS Volume",
                        "Status": "WARNING",
                        "FindingType": "Cost",
                        "Severity": "Medium",
                        "Details": f"EBS volume {volume_id} is unattached.",
                        "Recommendation": f"Consider deleting volume {volume_id}: aws ec2 delete-volume --volume-id {volume_id}",
                        "Timestamp": datetime.now(central).isoformat(),
                        "Compliance": {"AWS-Well-Architected": "COST-02"}
                    })
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "EBS",
            "Check": "EBS Volume Audit",
            "Status": "ERROR",
            "FindingType": "Error",
            "Severity": "Low",
            "Details": f"Error auditing EBS volumes: {str(e)}",
            "Recommendation": "Verify permissions for ec2:DescribeVolumes.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_ri_utilization(session, account_id):
    findings = []
    try:
        ce_client = session.client('ce', region_name='us-east-1')
        response = call_with_backoff(
            ce_client, 'get_reservation_utilization',
            TimePeriod={
                'Start': (datetime.now(ZoneInfo("UTC")).date() - timedelta(days=7)).strftime('%Y-%m-%d'),
                'End': datetime.now(ZoneInfo("UTC")).date().strftime('%Y-%m-%d')
            },
            Granularity='MONTHLY'
        )
        for group in response.get('UtilizationsByTime', []):
            total = group.get('Total', {})
            utilization_percentage = float(total.get('UtilizationPercentage', 0))
            if utilization_percentage < 80 and utilization_percentage > 0:
                findings.append({
                    "AccountId": account_id,
                    "Region": "global",
                    "Service": "CostExplorer",
                    "Check": "RI Utilization",
                    "Status": "WARNING",
                    "FindingType": "Cost",
                    "Severity": "Medium",
                    "Details": f"Reserved Instance utilization is {utilization_percentage:.2f}% (< 80%).",
                    "Recommendation": "Review RI usage in AWS Cost Explorer and consider modifying or selling unused RIs.",
                    "Timestamp": datetime.now(central).isoformat(),
                    "Compliance": {"AWS-Well-Architected": "COST-03"}
                })
            elif utilization_percentage == 0:
                findings.append({
                    "AccountId": account_id,
                    "Region": "global",
                    "Service": "CostExplorer",
                    "Check": "RI Utilization",
                    "Status": "WARNING",
                    "FindingType": "Cost",
                    "Severity": "High",
                    "Details": "No Reserved Instance utilization detected.",
                    "Recommendation": "Verify RI purchases or consider alternative purchasing options like Savings Plans.",
                    "Timestamp": datetime.now(central).isoformat(),
                    "Compliance": {"AWS-Well-Architected": "COST-03"}
                })
    except ClientError as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "CostExplorer",
            "Check": "RI Utilization Audit",
            "Status": "ERROR",
            "FindingType": "Error",
            "Severity": "Low",
            "Details": f"Error auditing RI utilization: {str(e)}",
            "Recommendation": "Verify permissions for ce:GetReservationUtilization.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings

def audit_cost(session, account_id, regions):
    """Main cost optimization audit function."""
    findings = []
    try:
        findings.extend(audit_high_cost_services(session, account_id))
        findings.extend(audit_idle_ec2_instances(session, account_id, regions))
        findings.extend(audit_unattached_ebs_volumes(session, account_id, regions))
        findings.extend(audit_ri_utilization(session, account_id))
        logger.info(f"Completed cost audit for account {account_id} with {len(findings)} findings.", extra={"account_id": account_id})
    except Exception as e:
        findings.append({
            "AccountId": account_id,
            "Region": "global",
            "Service": "CostExplorer",
            "Check": "Cost Audit",
            "Status": "ERROR",
            "FindingType": "Error",
            "Severity": "Low",
            "Details": f"Unexpected error in cost audit: {str(e)}",
            "Recommendation": "Review logs and verify cost audit configuration.",
            "Timestamp": datetime.now(central).isoformat(),
            "Compliance": {}
        })
    return findings
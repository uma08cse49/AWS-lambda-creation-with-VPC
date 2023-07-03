import boto3
import json
import os
import time
# ZIPNAME = os.path.dirname(os.path.abspath(__file__))+'/files/AWS-Config-Trigger.zip'
# INSTANCE_ZIPNAME = os.path.dirname(os.path.abspath(__file__))+'/files/CCOE_Track_Instance.zip'
# RESOURCE_ZIPNAME = os.path.dirname(os.path.abspath(__file__))+'/files/CCOE_Track_Resources.zip'

# session = boto3.session.Session(aws_access_key_id=os.environ['AWS_ACCESS_KEY'], aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],region_name = os.environ["DEFAULT_REGION_NAME"])

session=boto3.session.Session(aws_access_key_id=os.getenv("ACCESS_KEY_ID"),aws_secret_access_key=os.getenv("SECRET_ACCESS_KEY_ID"),region_name=os.getenv("REGION"))

region_name=os.getenv("REGION")
sts_client = session.client('sts')
org_client = session.client('organizations')
SNSClient = session.client('sns')
cloudwatchClient = session.client('logs')
default_region_name = region_name


def create_vpc_for_lambda(root_session):
    try:
        ec2_client = root_session.client('ec2', region_name = default_region_name)
        elastic_ip_1 = ec2_client.allocate_address(Domain='vpc')

        ec2 = root_session.resource('ec2', region_name = default_region_name)
        vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')
        # we can assign a name to vpc, or any resource, by using tag
        vpc.create_tags(Tags=[{"Key": "Name", "Value": "ccoe_vpc"}])
        vpc.wait_until_available()
        print("New VPC ID : ",vpc.id)

        ig = ec2.create_internet_gateway()
        vpc.attach_internet_gateway(InternetGatewayId=ig.id)
        print("New Interner Gateway : ",ig.id)

        public_route_table = vpc.create_route_table()
        public_route = public_route_table.create_route(
            DestinationCidrBlock='0.0.0.0/0',
            GatewayId=ig.id
        )

        ec2_client = root_session.client('ec2', region_name = default_region_name)

        public_subnet_1 = ec2_client.create_subnet(
            AvailabilityZone='us-east-1a',
            CidrBlock='10.0.16.0/20',
            VpcId=vpc.id
        )
        print("public subnets : ", public_subnet_1)


        public_route_table.associate_with_subnet(

            SubnetId=public_subnet_1['Subnet']['SubnetId'])


        nat_response1 = ec2_client.create_nat_gateway(
            AllocationId=elastic_ip_1['AllocationId'],
            SubnetId=public_subnet_1['Subnet']['SubnetId'],
            ConnectivityType='public'
        )

        private_subnet_1 = ec2_client.create_subnet(
            AvailabilityZone='us-east-1a',
            CidrBlock='10.0.144.0/20',
            VpcId=vpc.id,

        )
        print("private subnet1.....",private_subnet_1)
        time.sleep(5)

        # time.sleep(5)
        private_route_table_1 = vpc.create_route_table()
        private_route = private_route_table_1.create_route(
            DestinationCidrBlock='0.0.0.0/0',
            NatGatewayId=nat_response1["NatGateway"]["NatGatewayId"]
        )
        print(private_route_table_1)

        private_route_table_1.associate_with_subnet(
            SubnetId=private_subnet_1['Subnet']['SubnetId'])
        print("Nat", nat_response1)

        sg_response = ec2_client.describe_security_groups(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [
                        vpc.id
                    ]
                },
            ]
        )

        print(sg_response)
        print({
            "subnet_1": private_subnet_1['Subnet']['SubnetId'],
            # "subnet_2": private_subnet_2['Subnet']['SubnetId'],
            "security_group": sg_response['SecurityGroups'][0]["GroupId"],
            "nat_gateway_1": nat_response1['NatGateway']['NatGatewayId'],
            # "nat_gateway_2": nat_response2['NatGateway']['NatGatewayId']

        })
        return {
            "subnet_1": private_subnet_1['Subnet']['SubnetId'],
            # "subnet_2": private_subnet_2['Subnet']['SubnetId'],
            "security_group": sg_response['SecurityGroups'][0]["GroupId"],
            "nat_gateway_1": nat_response1['NatGateway']['NatGatewayId'],
            # "nat_gateway_2": nat_response2['NatGateway']['NatGatewayId']

        }
    except Exception as e:
        print(e)

def lambda_creator():
    # account_id = os.environ['ACCOUNT_ID']    
    # member_session = get_member_account_session(account_id)
    role_arn = None
    try:

        vpc_details = create_vpc_for_lambda(session)
        iam_client = session.client('iam', region_name = default_region_name)
        role_flag = False
        try:
            get_role_response = iam_client.get_role(RoleName = 'LambdaRoleForAWSConfig')
            role_flag = True
            role_arn = get_role_response['Role']['Arn']
        except Exception as e:
            print(e)
            role_flag = False

        print("Role flag : ", role_flag)

        
        if role_flag == False:
            assume_doc = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "lambda.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
            response = iam_client.create_role(
                RoleName='LambdaRoleForAWSConfig',
                AssumeRolePolicyDocument=json.dumps(assume_doc),
                Description='Lambda role for AWS Config'
            )
            print(response['Role']['Arn'])
            role_arn = response['Role']['Arn']

        response = iam_client.attach_role_policy(
            RoleName='LambdaRoleForAWSConfig', PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
        print("Attach Role : ",response)

        time.sleep(15)
        lambda_client = session.client('lambda', region_name = default_region_name)

        response = lambda_client.create_function(
            Code={
                # 'ZipFile': aws_file()
                'S3Bucket':'testpgmlambda', 'S3Key':'index.zip'
            },
            Description='',
            FunctionName='CCOE_Track_Resources',
            Handler='index.lambda_handler',
            Publish=True,
            Timeout=900,
            MemorySize=1024,
            Role=role_arn,
            # Environment={
            #     'Variables': {
            #         "ACCOUNT_TABLE" : "CCOE_Account_Types",
            #         "MANAGED_PATTERNS_TABLE" : "CCOE_Managed_Role_Patterns",
            #         "MANAGED_ROLES_TABLE" : "CCOE_Managed_Roles"
            #     }
            # },
            VpcConfig={
                'SubnetIds': [
                    vpc_details["subnet_1"], 
                    # vpc_details["subnet_2"]
                ],
                'SecurityGroupIds': [
                    vpc_details['security_group']
                ]
            },
            Runtime='python3.8',
        )
        print("Resource Responce : ",response)
        time.sleep(60)
        
        ec2_client = session.client('ec2', region_name = default_region_name)                                            

        nat_gateways = ec2_client.describe_nat_gateways(
            NatGatewayIds=[
                vpc_details["nat_gateway_1"], 
                # vpc_details["nat_gateway_2"]
            ])
        print(nat_gateways)
        print("Process of Lambda Creation is Done")  
    except Exception as e:
        print(e)  

    # print("Process of Lambda Creation is Done")              

def main():
    try:
        print("Start the Process")    
        log_group = "aws-cloudtrail-logs-all-accounts"
        lambda_creator()
        # create_resource_filter(log_group)
        # create_ec2_filter(log_group)
    
    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()        

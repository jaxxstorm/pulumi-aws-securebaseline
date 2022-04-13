import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";
import * as alarm from "./cloudwatchAlarm"

export interface CloudwatchApiAuditArgs {

  cloudTrailLogGroupName: pulumi.Input<string>;
  kmsMasterKeyId?: pulumi.Input<string>;
  alarmNamespace?: pulumi.Input<string>;
  enableAuthorizedApiCallsAlarm?: boolean;
  enableConsoleSigninWithoutMfaAlarm?: boolean;
  enableRootAccountUsageAlarm?: boolean;
  enableIamChangesAlarm?: boolean;
  enableCloudTrailConfigAlarm?: boolean;
  enableConsoleSigninFailureAlarm?: boolean;
  enableCmkModificationAlarm?: boolean;
  enableS3BucketPolicyChangesAlarm?: boolean;
  enableAwsConfigChangesAlarm?: boolean;
  enableSecurityGroupChangesAlarm?: boolean;
  enableNaclChangeAlarm?: boolean;
  enableNetworkGwChangesAlarm?: boolean;
  enableRouteTableChangesAlarm?: boolean;
  enableVpcChangesAlarm?: boolean;
  enableOrganizationsChangesAlarm?: boolean;
}

export class CloudwatchApiAudit extends pulumi.ComponentResource {
  public readonly snsTopic: aws.sns.Topic;
  public readonly snsTopicPolicy: aws.sns.TopicPolicy;

  constructor(
    name: string,
    args: CloudwatchApiAuditArgs,
    opts?: pulumi.ComponentResourceOptions
  ) {
    super("securebaseline:index:CloudwatchApiAudit", name, args, opts);

    this.snsTopic = new aws.sns.Topic(name, {
      kmsMasterKeyId: args.kmsMasterKeyId,
    }, { parent: this });

    let region = aws.getRegionOutput();
    let account = aws.getCallerIdentity().then((id) => id.accountId);

    this.snsTopicPolicy = new aws.sns.TopicPolicy(name, {
      arn: this.snsTopic.arn,
      policy: pulumi
        .all([this.snsTopic.arn, region.name, account])
        .apply(([topicArn, region, accountId]) =>
          JSON.stringify({
            Version: "2012-10-17",
            Statement: [
              {
                Action: "sns:Publish",
                Resource: topicArn,
                Principal: {
                  Service: "cloudwatch.amazonaws.com",
                },
                Condition: {
                  ArnLike: {
                    "aws:SourceArn": `arn:aws:cloudwatch:${region}:${accountId}:alarm:*`,
                  },
                },
              },
            ],
          })
        ),
    }, { parent: this.snsTopic });

    if (args.enableAuthorizedApiCallsAlarm != false) {
      new alarm.CloudwatchAlarm(`${name}-unauthorizedApiCalls`, {
        pattern: "{(($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\")) && (($.sourceIPAddress!=\"delivery.logs.amazonaws.com\") && ($.eventName!=\"HeadBucket\"))}",
        name: "UnauthorizedAPICalls",
        cloudTrailLogGroupName: args.cloudTrailLogGroupName,
        alarmActions: [ this.snsTopic.arn ],
        alarmDescription: "Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity."
      }, { parent: this })
    }

    if (args.enableConsoleSigninWithoutMfaAlarm != false) {
      new alarm.CloudwatchAlarm(`${name}-mfaConsoleSignin`, {
        pattern: "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") && ($.userIdentity.type = \"IAMUser\") && ($.responseElements.ConsoleLogin = \"Success\") }",
        name: "NoMFAConsoleSignin",
        cloudTrailLogGroupName: args.cloudTrailLogGroupName,
        alarmActions: [ this.snsTopic.arn ],
        alarmDescription: "Monitoring for single-factor console logins will increase visibility into accounts that are not protected by MFA."
      }, { parent: this })
    }

    if (args.enableIamChangesAlarm != false) {
      new alarm.CloudwatchAlarm(`${name}-iamChanges`, {
        pattern: "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}",
        name: "IamChanges",
        cloudTrailLogGroupName: args.cloudTrailLogGroupName,
        alarmActions: [ this.snsTopic.arn ],
        alarmDescription: "Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact."
      }, { parent: this })
    }

    if (args.enableCloudTrailConfigAlarm != false) {
      new alarm.CloudwatchAlarm(`${name}-cloudTrailConfigChanges`, {
        pattern: "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }",
        name: "CloudTrailChanges",
        cloudTrailLogGroupName: args.cloudTrailLogGroupName,
        alarmActions: [ this.snsTopic.arn ],
        alarmDescription: "Monitoring changes to CloudTrail's configuration will help ensure sustained visibility to activities performed in the AWS account."
      }, { parent: this })
    }

    if (args.enableConsoleSigninFailureAlarm != false) {
      new alarm.CloudwatchAlarm(`${name}-consoleSignInFailure`, {
        pattern: "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }",
        name: "ConsoleSiginFailure",
        cloudTrailLogGroupName: args.cloudTrailLogGroupName,
        alarmActions: [ this.snsTopic.arn ],
        alarmDescription: "Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation."
      }, { parent: this })
    }

    if (args.enableCmkModificationAlarm != false) {
      new alarm.CloudwatchAlarm(`${name}-cmkModificationAlarm`, {
        pattern: "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }",
        name: "CmkModification",
        cloudTrailLogGroupName: args.cloudTrailLogGroupName,
        alarmActions: [ this.snsTopic.arn ],
        alarmDescription: "Deleting or removing a CMK could mean an attempt to unencrypt data."
      }, { parent: this })
    }

    if (args.enableS3BucketPolicyChangesAlarm != false) {
      new alarm.CloudwatchAlarm(`${name}-s3BucketPolicyChangesAlarm`, {
        pattern: "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }",
        name: "S3BucketPolicyChanges",
        cloudTrailLogGroupName: args.cloudTrailLogGroupName,
        alarmActions: [ this.snsTopic.arn ],
        alarmDescription: "Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets."
      }, { parent: this })
    }

    if (args.enableAwsConfigChangesAlarm != false) {
      new alarm.CloudwatchAlarm(`${name}-configChanges`, {
        pattern: "{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }",
        name: "AWSConfigChanges",
        cloudTrailLogGroupName: args.cloudTrailLogGroupName,
        alarmActions: [ this.snsTopic.arn ],
        alarmDescription: "Monitoring changes to AWS Config configuration will help ensure sustained visibility of configuration items within the AWS account."
      }, { parent: this })
    }

    if (args.enableSecurityGroupChangesAlarm != false) {
      new alarm.CloudwatchAlarm(`${name}-securityGroupChanges`, {
        pattern: "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}",
        name: "SecurityGroupChanges",
        cloudTrailLogGroupName: args.cloudTrailLogGroupName,
        alarmActions: [ this.snsTopic.arn ],
        alarmDescription: "Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed."
      }, { parent: this })
    }

    if (args.enableNaclChangeAlarm != false) {
      new alarm.CloudwatchAlarm(`${name}-naclChanges`, {
        pattern: "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }",
        name: "NaclChanges",
        cloudTrailLogGroupName: args.cloudTrailLogGroupName,
        alarmActions: [ this.snsTopic.arn ],
        alarmDescription: "Monitoring changes to NACLs will help ensure that AWS resources and services are not unintentionally exposed."
      }, { parent: this })
    }

    if (args.enableNetworkGwChangesAlarm != false) {
      new alarm.CloudwatchAlarm(`${name}-nwGatewayChanges`, {
        pattern: "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }",
        name: "NetworkGatewayChanges",
        cloudTrailLogGroupName: args.cloudTrailLogGroupName,
        alarmActions: [ this.snsTopic.arn ],
        alarmDescription: "Monitoring changes to network gateways will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path."
      }, { parent: this })
    }

    if (args.enableRouteTableChangesAlarm != false) {
      new alarm.CloudwatchAlarm(`${name}-routeTableChanges`, {
        pattern: "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }",
        name: "RouteTableChanges",
        cloudTrailLogGroupName: args.cloudTrailLogGroupName,
        alarmActions: [ this.snsTopic.arn ],
        alarmDescription: "Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path."
      }, { parent: this })
    }

    if (args.enableVpcChangesAlarm != false) {
      new alarm.CloudwatchAlarm(`${name}-vpcChanges`, {
        pattern: "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }",
        name: "VpcChanges",
        cloudTrailLogGroupName: args.cloudTrailLogGroupName,
        alarmActions: [ this.snsTopic.arn ],
        alarmDescription: "Monitoring changes to VPC will help ensure that all VPC traffic flows through an expected path."
      }, { parent: this })
    }

    if (args.enableOrganizationsChangesAlarm != false) {
      new alarm.CloudwatchAlarm(`${name}-enableOrganizations`, {
        pattern: "{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = \"AcceptHandshake\") || ($.eventName = \"AttachPolicy\") || ($.eventName = \"CreateAccount\") || ($.eventName = \"CreateOrganizationalUnit\") || ($.eventName= \"CreatePolicy\") || ($.eventName = \"DeclineHandshake\") || ($.eventName = \"DeleteOrganization\") || ($.eventName = \"DeleteOrganizationalUnit\") || ($.eventName = \"DeletePolicy\") || ($.eventName = \"DetachPolicy\") || ($.eventName = \"DisablePolicyType\") || ($.eventName = \"EnablePolicyType\") || ($.eventName = \"InviteAccountToOrganization\") || ($.eventName = \"LeaveOrganization\") || ($.eventName = \"MoveAccount\") || ($.eventName = \"RemoveAccountFromOrganization\") || ($.eventName = \"UpdatePolicy\") || ($.eventName =\"UpdateOrganizationalUnit\")) }",
        name: "VpcChanges",
        cloudTrailLogGroupName: args.cloudTrailLogGroupName,
        alarmActions: [ this.snsTopic.arn ],
        alarmDescription: "Monitoring AWS Organizations changes can help you prevent any unwanted, accidental or intentional modifications that may lead to unauthorized access or other security breaches."
      }, { parent: this })
    }

    

    this.registerOutputs({});
  }
}

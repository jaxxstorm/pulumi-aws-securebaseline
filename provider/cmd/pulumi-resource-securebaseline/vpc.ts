import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

export interface VpcArgs {
  tags?: aws.Tags;
  enableFlowLogs?: boolean;
  iamRoleArn?: pulumi.Input<string>;
  flowLogRetentionDays?: pulumi.Input<number>;
}

export class Vpc extends pulumi.ComponentResource {
  public readonly defaultVpc: aws.ec2.DefaultVpc;
  public readonly defaultVpcFlowLogGroup?: aws.cloudwatch.LogGroup;
  public readonly defaultVpcFlowLog?: aws.ec2.FlowLog;

  constructor(
    name: string,
    args: VpcArgs,
    opts?: pulumi.ComponentResourceOptions
  ) {
    super("securebaseline:index:Vpc", name, args, opts);

    this.defaultVpc = new aws.ec2.DefaultVpc(
      name,
      {
        //tags: Object.assign(args.tags!, { Default: "true" }),
        tags: { Default: "true", ...args.tags },
      },
      { parent: this }
    );

    let subnets = aws.ec2.getSubnets({
      filters: [
        {
          name: "default-for-az",
          values: ["true"],
        },
      ],
    });

    subnets.then((subnets) =>
      subnets.ids.forEach((id) => {
        let subnet = aws.ec2.getSubnetOutput({
          id: id,
        });
        new aws.ec2.DefaultSubnet(
          `${name}-${id}`,
          {
            availabilityZone: subnet.availabilityZone,
            mapPublicIpOnLaunch: false,
            tags: { Default: "true", ...args.tags },
          },
          { parent: this.defaultVpc }
        );
      })
    );

    new aws.ec2.DefaultRouteTable(
      name,
      {
        defaultRouteTableId: this.defaultVpc.defaultRouteTableId,
        tags: { Default: "true", ...args.tags },
      },
      { parent: this.defaultVpc }
    );

    new aws.ec2.DefaultSecurityGroup(
      name,
      {
        vpcId: this.defaultVpc.id,
        tags: { Default: "true", ...args.tags },
      },
      { parent: this.defaultVpc }
    );

    if (args.enableFlowLogs) {
      // FIXME: add support for s3 destination type
      this.defaultVpcFlowLogGroup = new aws.cloudwatch.LogGroup(name, {
        retentionInDays: args.flowLogRetentionDays || 365,
        tags: { ...args.tags },
      });

      this.defaultVpcFlowLog = new aws.ec2.FlowLog(name, {
        logDestinationType: "cloud-watch-logs",
        iamRoleArn: args.iamRoleArn,
        trafficType: "ALL",
        vpcId: this.defaultVpc.id,
      });
    }

    this.registerOutputs({});
  }
}

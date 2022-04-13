import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

export interface IamArgs {
  enablePasswordPolicy?: boolean;
  enableSupportRole?: boolean;
  supportRolePrincipalArns?: pulumi.Input<string>[];
  minimumPasswordLength?: pulumi.Input<number>;
  passwordReusePrevention?: pulumi.Input<number>;
  requireLowercaseCharacters?: pulumi.Input<boolean>;
  requireNumbers?: pulumi.Input<boolean>;
  requireUppercaseCharacters?: pulumi.Input<boolean>;
  requireSymbols?: pulumi.Input<boolean>;
  allowUsersToChangePassword?: pulumi.Input<boolean>;
}

export class Iam extends pulumi.ComponentResource {
  public readonly supportRole?: aws.iam.Role;
  public readonly iamAccountPasswordPolicy?: aws.iam.AccountPasswordPolicy;

  constructor(
    name: string,
    args: IamArgs,
    opts?: pulumi.ComponentResourceOptions
  ) {
    super("securebaseline:index:Iam", name, args, opts);

    if (args.enableSupportRole != false) {
      this.supportRole = new aws.iam.Role(
        name,
        {
          assumeRolePolicy: pulumi
            .all(args.supportRolePrincipalArns)
            .apply((arns) =>
              JSON.stringify({
                Version: "2012-10-17",
                Statement: [
                  {
                    Action: "sts:AssumeRole",
                    Principal: {
                      AWS: arns,
                    },
                  },
                ],
              })
            ),
        },
        { parent: this }
      );

      new aws.iam.RolePolicyAttachment(
        name,
        {
          role: this.supportRole.id,
          policyArn: "arn:aws:iam::aws:policy/AWSSupportAccess",
        },
        { parent: this.supportRole }
      );
    }

    if (args.enablePasswordPolicy != false) {
      this.iamAccountPasswordPolicy = new aws.iam.AccountPasswordPolicy(
        name,
        {
          minimumPasswordLength: args.minimumPasswordLength || 14,
          passwordReusePrevention: args.passwordReusePrevention || 24,
          requireLowercaseCharacters: args.requireLowercaseCharacters || true,
          requireNumbers: args.requireNumbers || true,
          requireUppercaseCharacters: args.requireUppercaseCharacters || true,
          requireSymbols: args.requireSymbols || true,
          allowUsersToChangePassword: args.allowUsersToChangePassword || true,
        },
        { parent: this }
      );
    }

    this.registerOutputs({});
  }
}

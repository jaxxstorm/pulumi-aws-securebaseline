import * as pulumi from "@pulumi/pulumi";
import * as aws from "@pulumi/aws";

export interface SecurityHubMemberAccount {
  accountId: pulumi.Input<string>
  email: pulumi.Input<string>
}

export interface SecurityHubArgs {
  aggregate?: boolean;
  masterAccountId?: pulumi.Input<string>;
  memberAccounts: SecurityHubMemberAccount[];
}

export class SecurityHub extends pulumi.ComponentResource {

  public readonly securityHubAccount: aws.securityhub.Account

  constructor(
    name: string,
    args: SecurityHubArgs,
    opts?: pulumi.ComponentResourceOptions
  ) {
    super("securebaseline:index:SecurityHub", name, args, opts);

    this.securityHubAccount = new aws.securityhub.Account(name, {})

    if (args.aggregate) {
      new aws.securityhub.FindingAggregator(name, {
        linkingMode: "ALL_REGIONS",
      }, { dependsOn: this.securityHubAccount })
    }

    args.memberAccounts.forEach(account => {
      new aws.securityhub.Member(name, {
        accountId: account.accountId,
        email: account.email,
        invite: true,
      })
      
    });
    

    this.registerOutputs({});
  }
}

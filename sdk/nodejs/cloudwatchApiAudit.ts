// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

import * as pulumi from "@pulumi/pulumi";
import * as utilities from "./utilities";

export class CloudwatchApiAudit extends pulumi.ComponentResource {
    /** @internal */
    public static readonly __pulumiType = 'securebaseline:index:CloudwatchApiAudit';

    /**
     * Returns true if the given object is an instance of CloudwatchApiAudit.  This is designed to work even
     * when multiple copies of the Pulumi SDK have been loaded into the same process.
     */
    public static isInstance(obj: any): obj is CloudwatchApiAudit {
        if (obj === undefined || obj === null) {
            return false;
        }
        return obj['__pulumiType'] === CloudwatchApiAudit.__pulumiType;
    }


    /**
     * Create a CloudwatchApiAudit resource with the given unique name, arguments, and options.
     *
     * @param name The _unique_ name of the resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param opts A bag of options that control this resource's behavior.
     */
    constructor(name: string, args?: CloudwatchApiAuditArgs, opts?: pulumi.ComponentResourceOptions) {
        let resourceInputs: pulumi.Inputs = {};
        opts = opts || {};
        if (!opts.id) {
            resourceInputs["enableAuthorizedApiCallsAlarm"] = args ? args.enableAuthorizedApiCallsAlarm : undefined;
            resourceInputs["enableAwsConfigChangesAlarm"] = args ? args.enableAwsConfigChangesAlarm : undefined;
            resourceInputs["enableCmkModificationAlarm"] = args ? args.enableCmkModificationAlarm : undefined;
            resourceInputs["enableConsoleSigninFailureAlarm "] = args ? args.enableConsoleSigninFailureAlarm  : undefined;
            resourceInputs["enableConsoleSigninWithoutMfaAlarm"] = args ? args.enableConsoleSigninWithoutMfaAlarm : undefined;
            resourceInputs["enableIamChangesAlarm"] = args ? args.enableIamChangesAlarm : undefined;
            resourceInputs["enableNaclChangeAlarm"] = args ? args.enableNaclChangeAlarm : undefined;
            resourceInputs["enableNetworkGwChangesAlarm"] = args ? args.enableNetworkGwChangesAlarm : undefined;
            resourceInputs["enableOrganizationsChangesAlarm"] = args ? args.enableOrganizationsChangesAlarm : undefined;
            resourceInputs["enableRootAccountUsageAlarm"] = args ? args.enableRootAccountUsageAlarm : undefined;
            resourceInputs["enableRouteTableChangesAlarm"] = args ? args.enableRouteTableChangesAlarm : undefined;
            resourceInputs["enableS3BucketPolicyChangesAlarm"] = args ? args.enableS3BucketPolicyChangesAlarm : undefined;
            resourceInputs["enableSecurityGroupChangesAlarm"] = args ? args.enableSecurityGroupChangesAlarm : undefined;
            resourceInputs["enableVpcChangesAlarm"] = args ? args.enableVpcChangesAlarm : undefined;
        } else {
        }
        opts = pulumi.mergeOptions(utilities.resourceOptsDefaults(), opts);
        super(CloudwatchApiAudit.__pulumiType, name, resourceInputs, opts, true /*remote*/);
    }
}

/**
 * The set of arguments for constructing a CloudwatchApiAudit resource.
 */
export interface CloudwatchApiAuditArgs {
    enableAuthorizedApiCallsAlarm?: pulumi.Input<boolean>;
    enableAwsConfigChangesAlarm?: pulumi.Input<boolean>;
    enableCmkModificationAlarm?: pulumi.Input<boolean>;
    enableConsoleSigninFailureAlarm ?: pulumi.Input<boolean>;
    enableConsoleSigninWithoutMfaAlarm?: pulumi.Input<boolean>;
    enableIamChangesAlarm?: pulumi.Input<boolean>;
    enableNaclChangeAlarm?: pulumi.Input<boolean>;
    enableNetworkGwChangesAlarm?: pulumi.Input<boolean>;
    enableOrganizationsChangesAlarm?: pulumi.Input<boolean>;
    enableRootAccountUsageAlarm?: pulumi.Input<boolean>;
    enableRouteTableChangesAlarm?: pulumi.Input<boolean>;
    enableS3BucketPolicyChangesAlarm?: pulumi.Input<boolean>;
    enableSecurityGroupChangesAlarm?: pulumi.Input<boolean>;
    enableVpcChangesAlarm?: pulumi.Input<boolean>;
}

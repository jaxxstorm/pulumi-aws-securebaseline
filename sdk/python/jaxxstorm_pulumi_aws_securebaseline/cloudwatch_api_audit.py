# coding=utf-8
# *** WARNING: this file was generated by Pulumi SDK Generator. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from . import _utilities

__all__ = ['CloudwatchApiAuditArgs', 'CloudwatchApiAudit']

@pulumi.input_type
class CloudwatchApiAuditArgs:
    def __init__(__self__, *,
                 cloud_trail_log_group_name: pulumi.Input[str],
                 enable_authorized_api_calls_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_aws_config_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_cmk_modification_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_console_signin_failure_alarm_: Optional[pulumi.Input[bool]] = None,
                 enable_console_signin_without_mfa_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_iam_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_nacl_change_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_network_gw_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_organizations_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_root_account_usage_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_route_table_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_s3_bucket_policy_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_security_group_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_vpc_changes_alarm: Optional[pulumi.Input[bool]] = None):
        """
        The set of arguments for constructing a CloudwatchApiAudit resource.
        """
        pulumi.set(__self__, "cloud_trail_log_group_name", cloud_trail_log_group_name)
        if enable_authorized_api_calls_alarm is not None:
            pulumi.set(__self__, "enable_authorized_api_calls_alarm", enable_authorized_api_calls_alarm)
        if enable_aws_config_changes_alarm is not None:
            pulumi.set(__self__, "enable_aws_config_changes_alarm", enable_aws_config_changes_alarm)
        if enable_cmk_modification_alarm is not None:
            pulumi.set(__self__, "enable_cmk_modification_alarm", enable_cmk_modification_alarm)
        if enable_console_signin_failure_alarm_ is not None:
            pulumi.set(__self__, "enable_console_signin_failure_alarm_", enable_console_signin_failure_alarm_)
        if enable_console_signin_without_mfa_alarm is not None:
            pulumi.set(__self__, "enable_console_signin_without_mfa_alarm", enable_console_signin_without_mfa_alarm)
        if enable_iam_changes_alarm is not None:
            pulumi.set(__self__, "enable_iam_changes_alarm", enable_iam_changes_alarm)
        if enable_nacl_change_alarm is not None:
            pulumi.set(__self__, "enable_nacl_change_alarm", enable_nacl_change_alarm)
        if enable_network_gw_changes_alarm is not None:
            pulumi.set(__self__, "enable_network_gw_changes_alarm", enable_network_gw_changes_alarm)
        if enable_organizations_changes_alarm is not None:
            pulumi.set(__self__, "enable_organizations_changes_alarm", enable_organizations_changes_alarm)
        if enable_root_account_usage_alarm is not None:
            pulumi.set(__self__, "enable_root_account_usage_alarm", enable_root_account_usage_alarm)
        if enable_route_table_changes_alarm is not None:
            pulumi.set(__self__, "enable_route_table_changes_alarm", enable_route_table_changes_alarm)
        if enable_s3_bucket_policy_changes_alarm is not None:
            pulumi.set(__self__, "enable_s3_bucket_policy_changes_alarm", enable_s3_bucket_policy_changes_alarm)
        if enable_security_group_changes_alarm is not None:
            pulumi.set(__self__, "enable_security_group_changes_alarm", enable_security_group_changes_alarm)
        if enable_vpc_changes_alarm is not None:
            pulumi.set(__self__, "enable_vpc_changes_alarm", enable_vpc_changes_alarm)

    @property
    @pulumi.getter(name="cloudTrailLogGroupName")
    def cloud_trail_log_group_name(self) -> pulumi.Input[str]:
        return pulumi.get(self, "cloud_trail_log_group_name")

    @cloud_trail_log_group_name.setter
    def cloud_trail_log_group_name(self, value: pulumi.Input[str]):
        pulumi.set(self, "cloud_trail_log_group_name", value)

    @property
    @pulumi.getter(name="enableAuthorizedApiCallsAlarm")
    def enable_authorized_api_calls_alarm(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "enable_authorized_api_calls_alarm")

    @enable_authorized_api_calls_alarm.setter
    def enable_authorized_api_calls_alarm(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_authorized_api_calls_alarm", value)

    @property
    @pulumi.getter(name="enableAwsConfigChangesAlarm")
    def enable_aws_config_changes_alarm(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "enable_aws_config_changes_alarm")

    @enable_aws_config_changes_alarm.setter
    def enable_aws_config_changes_alarm(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_aws_config_changes_alarm", value)

    @property
    @pulumi.getter(name="enableCmkModificationAlarm")
    def enable_cmk_modification_alarm(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "enable_cmk_modification_alarm")

    @enable_cmk_modification_alarm.setter
    def enable_cmk_modification_alarm(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_cmk_modification_alarm", value)

    @property
    @pulumi.getter(name="enableConsoleSigninFailureAlarm ")
    def enable_console_signin_failure_alarm_(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "enable_console_signin_failure_alarm_")

    @enable_console_signin_failure_alarm_.setter
    def enable_console_signin_failure_alarm_(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_console_signin_failure_alarm_", value)

    @property
    @pulumi.getter(name="enableConsoleSigninWithoutMfaAlarm")
    def enable_console_signin_without_mfa_alarm(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "enable_console_signin_without_mfa_alarm")

    @enable_console_signin_without_mfa_alarm.setter
    def enable_console_signin_without_mfa_alarm(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_console_signin_without_mfa_alarm", value)

    @property
    @pulumi.getter(name="enableIamChangesAlarm")
    def enable_iam_changes_alarm(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "enable_iam_changes_alarm")

    @enable_iam_changes_alarm.setter
    def enable_iam_changes_alarm(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_iam_changes_alarm", value)

    @property
    @pulumi.getter(name="enableNaclChangeAlarm")
    def enable_nacl_change_alarm(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "enable_nacl_change_alarm")

    @enable_nacl_change_alarm.setter
    def enable_nacl_change_alarm(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_nacl_change_alarm", value)

    @property
    @pulumi.getter(name="enableNetworkGwChangesAlarm")
    def enable_network_gw_changes_alarm(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "enable_network_gw_changes_alarm")

    @enable_network_gw_changes_alarm.setter
    def enable_network_gw_changes_alarm(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_network_gw_changes_alarm", value)

    @property
    @pulumi.getter(name="enableOrganizationsChangesAlarm")
    def enable_organizations_changes_alarm(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "enable_organizations_changes_alarm")

    @enable_organizations_changes_alarm.setter
    def enable_organizations_changes_alarm(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_organizations_changes_alarm", value)

    @property
    @pulumi.getter(name="enableRootAccountUsageAlarm")
    def enable_root_account_usage_alarm(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "enable_root_account_usage_alarm")

    @enable_root_account_usage_alarm.setter
    def enable_root_account_usage_alarm(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_root_account_usage_alarm", value)

    @property
    @pulumi.getter(name="enableRouteTableChangesAlarm")
    def enable_route_table_changes_alarm(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "enable_route_table_changes_alarm")

    @enable_route_table_changes_alarm.setter
    def enable_route_table_changes_alarm(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_route_table_changes_alarm", value)

    @property
    @pulumi.getter(name="enableS3BucketPolicyChangesAlarm")
    def enable_s3_bucket_policy_changes_alarm(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "enable_s3_bucket_policy_changes_alarm")

    @enable_s3_bucket_policy_changes_alarm.setter
    def enable_s3_bucket_policy_changes_alarm(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_s3_bucket_policy_changes_alarm", value)

    @property
    @pulumi.getter(name="enableSecurityGroupChangesAlarm")
    def enable_security_group_changes_alarm(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "enable_security_group_changes_alarm")

    @enable_security_group_changes_alarm.setter
    def enable_security_group_changes_alarm(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_security_group_changes_alarm", value)

    @property
    @pulumi.getter(name="enableVpcChangesAlarm")
    def enable_vpc_changes_alarm(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "enable_vpc_changes_alarm")

    @enable_vpc_changes_alarm.setter
    def enable_vpc_changes_alarm(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_vpc_changes_alarm", value)


class CloudwatchApiAudit(pulumi.ComponentResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 cloud_trail_log_group_name: Optional[pulumi.Input[str]] = None,
                 enable_authorized_api_calls_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_aws_config_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_cmk_modification_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_console_signin_failure_alarm_: Optional[pulumi.Input[bool]] = None,
                 enable_console_signin_without_mfa_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_iam_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_nacl_change_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_network_gw_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_organizations_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_root_account_usage_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_route_table_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_s3_bucket_policy_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_security_group_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_vpc_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 __props__=None):
        """
        Create a CloudwatchApiAudit resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: CloudwatchApiAuditArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        Create a CloudwatchApiAudit resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param CloudwatchApiAuditArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(CloudwatchApiAuditArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 cloud_trail_log_group_name: Optional[pulumi.Input[str]] = None,
                 enable_authorized_api_calls_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_aws_config_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_cmk_modification_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_console_signin_failure_alarm_: Optional[pulumi.Input[bool]] = None,
                 enable_console_signin_without_mfa_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_iam_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_nacl_change_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_network_gw_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_organizations_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_root_account_usage_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_route_table_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_s3_bucket_policy_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_security_group_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 enable_vpc_changes_alarm: Optional[pulumi.Input[bool]] = None,
                 __props__=None):
        if opts is None:
            opts = pulumi.ResourceOptions()
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.version is None:
            opts.version = _utilities.get_version()
        if opts.id is not None:
            raise ValueError('ComponentResource classes do not support opts.id')
        else:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = CloudwatchApiAuditArgs.__new__(CloudwatchApiAuditArgs)

            if cloud_trail_log_group_name is None and not opts.urn:
                raise TypeError("Missing required property 'cloud_trail_log_group_name'")
            __props__.__dict__["cloud_trail_log_group_name"] = cloud_trail_log_group_name
            __props__.__dict__["enable_authorized_api_calls_alarm"] = enable_authorized_api_calls_alarm
            __props__.__dict__["enable_aws_config_changes_alarm"] = enable_aws_config_changes_alarm
            __props__.__dict__["enable_cmk_modification_alarm"] = enable_cmk_modification_alarm
            __props__.__dict__["enable_console_signin_failure_alarm_"] = enable_console_signin_failure_alarm_
            __props__.__dict__["enable_console_signin_without_mfa_alarm"] = enable_console_signin_without_mfa_alarm
            __props__.__dict__["enable_iam_changes_alarm"] = enable_iam_changes_alarm
            __props__.__dict__["enable_nacl_change_alarm"] = enable_nacl_change_alarm
            __props__.__dict__["enable_network_gw_changes_alarm"] = enable_network_gw_changes_alarm
            __props__.__dict__["enable_organizations_changes_alarm"] = enable_organizations_changes_alarm
            __props__.__dict__["enable_root_account_usage_alarm"] = enable_root_account_usage_alarm
            __props__.__dict__["enable_route_table_changes_alarm"] = enable_route_table_changes_alarm
            __props__.__dict__["enable_s3_bucket_policy_changes_alarm"] = enable_s3_bucket_policy_changes_alarm
            __props__.__dict__["enable_security_group_changes_alarm"] = enable_security_group_changes_alarm
            __props__.__dict__["enable_vpc_changes_alarm"] = enable_vpc_changes_alarm
        super(CloudwatchApiAudit, __self__).__init__(
            'securebaseline:index:CloudwatchApiAudit',
            resource_name,
            __props__,
            opts,
            remote=True)

# coding=utf-8
# *** WARNING: this file was generated by Pulumi SDK Generator. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from . import _utilities

__all__ = ['IamArgs', 'Iam']

@pulumi.input_type
class IamArgs:
    def __init__(__self__, *,
                 allow_users_to_change_password: Optional[pulumi.Input[bool]] = None,
                 enable_password_policy: Optional[pulumi.Input[bool]] = None,
                 enable_support_role: Optional[pulumi.Input[bool]] = None,
                 minimum_password_length: Optional[pulumi.Input[float]] = None,
                 password_reuse_prevention: Optional[pulumi.Input[float]] = None,
                 require_lowercase_characters: Optional[pulumi.Input[bool]] = None,
                 require_numbers: Optional[pulumi.Input[bool]] = None,
                 require_symbols: Optional[pulumi.Input[bool]] = None,
                 require_uppercase_characters: Optional[pulumi.Input[bool]] = None):
        """
        The set of arguments for constructing a Iam resource.
        """
        if allow_users_to_change_password is not None:
            pulumi.set(__self__, "allow_users_to_change_password", allow_users_to_change_password)
        if enable_password_policy is not None:
            pulumi.set(__self__, "enable_password_policy", enable_password_policy)
        if enable_support_role is not None:
            pulumi.set(__self__, "enable_support_role", enable_support_role)
        if minimum_password_length is not None:
            pulumi.set(__self__, "minimum_password_length", minimum_password_length)
        if password_reuse_prevention is not None:
            pulumi.set(__self__, "password_reuse_prevention", password_reuse_prevention)
        if require_lowercase_characters is not None:
            pulumi.set(__self__, "require_lowercase_characters", require_lowercase_characters)
        if require_numbers is not None:
            pulumi.set(__self__, "require_numbers", require_numbers)
        if require_symbols is not None:
            pulumi.set(__self__, "require_symbols", require_symbols)
        if require_uppercase_characters is not None:
            pulumi.set(__self__, "require_uppercase_characters", require_uppercase_characters)

    @property
    @pulumi.getter(name="allowUsersToChangePassword")
    def allow_users_to_change_password(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "allow_users_to_change_password")

    @allow_users_to_change_password.setter
    def allow_users_to_change_password(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "allow_users_to_change_password", value)

    @property
    @pulumi.getter(name="enablePasswordPolicy")
    def enable_password_policy(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "enable_password_policy")

    @enable_password_policy.setter
    def enable_password_policy(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_password_policy", value)

    @property
    @pulumi.getter(name="enableSupportRole")
    def enable_support_role(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "enable_support_role")

    @enable_support_role.setter
    def enable_support_role(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "enable_support_role", value)

    @property
    @pulumi.getter(name="minimumPasswordLength")
    def minimum_password_length(self) -> Optional[pulumi.Input[float]]:
        return pulumi.get(self, "minimum_password_length")

    @minimum_password_length.setter
    def minimum_password_length(self, value: Optional[pulumi.Input[float]]):
        pulumi.set(self, "minimum_password_length", value)

    @property
    @pulumi.getter(name="passwordReusePrevention")
    def password_reuse_prevention(self) -> Optional[pulumi.Input[float]]:
        return pulumi.get(self, "password_reuse_prevention")

    @password_reuse_prevention.setter
    def password_reuse_prevention(self, value: Optional[pulumi.Input[float]]):
        pulumi.set(self, "password_reuse_prevention", value)

    @property
    @pulumi.getter(name="requireLowercaseCharacters")
    def require_lowercase_characters(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "require_lowercase_characters")

    @require_lowercase_characters.setter
    def require_lowercase_characters(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "require_lowercase_characters", value)

    @property
    @pulumi.getter(name="requireNumbers")
    def require_numbers(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "require_numbers")

    @require_numbers.setter
    def require_numbers(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "require_numbers", value)

    @property
    @pulumi.getter(name="requireSymbols")
    def require_symbols(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "require_symbols")

    @require_symbols.setter
    def require_symbols(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "require_symbols", value)

    @property
    @pulumi.getter(name="requireUppercaseCharacters")
    def require_uppercase_characters(self) -> Optional[pulumi.Input[bool]]:
        return pulumi.get(self, "require_uppercase_characters")

    @require_uppercase_characters.setter
    def require_uppercase_characters(self, value: Optional[pulumi.Input[bool]]):
        pulumi.set(self, "require_uppercase_characters", value)


class Iam(pulumi.ComponentResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 allow_users_to_change_password: Optional[pulumi.Input[bool]] = None,
                 enable_password_policy: Optional[pulumi.Input[bool]] = None,
                 enable_support_role: Optional[pulumi.Input[bool]] = None,
                 minimum_password_length: Optional[pulumi.Input[float]] = None,
                 password_reuse_prevention: Optional[pulumi.Input[float]] = None,
                 require_lowercase_characters: Optional[pulumi.Input[bool]] = None,
                 require_numbers: Optional[pulumi.Input[bool]] = None,
                 require_symbols: Optional[pulumi.Input[bool]] = None,
                 require_uppercase_characters: Optional[pulumi.Input[bool]] = None,
                 __props__=None):
        """
        Create a Iam resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: Optional[IamArgs] = None,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        Create a Iam resource with the given unique name, props, and options.
        :param str resource_name: The name of the resource.
        :param IamArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(IamArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 allow_users_to_change_password: Optional[pulumi.Input[bool]] = None,
                 enable_password_policy: Optional[pulumi.Input[bool]] = None,
                 enable_support_role: Optional[pulumi.Input[bool]] = None,
                 minimum_password_length: Optional[pulumi.Input[float]] = None,
                 password_reuse_prevention: Optional[pulumi.Input[float]] = None,
                 require_lowercase_characters: Optional[pulumi.Input[bool]] = None,
                 require_numbers: Optional[pulumi.Input[bool]] = None,
                 require_symbols: Optional[pulumi.Input[bool]] = None,
                 require_uppercase_characters: Optional[pulumi.Input[bool]] = None,
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
            __props__ = IamArgs.__new__(IamArgs)

            __props__.__dict__["allow_users_to_change_password"] = allow_users_to_change_password
            __props__.__dict__["enable_password_policy"] = enable_password_policy
            __props__.__dict__["enable_support_role"] = enable_support_role
            __props__.__dict__["minimum_password_length"] = minimum_password_length
            __props__.__dict__["password_reuse_prevention"] = password_reuse_prevention
            __props__.__dict__["require_lowercase_characters"] = require_lowercase_characters
            __props__.__dict__["require_numbers"] = require_numbers
            __props__.__dict__["require_symbols"] = require_symbols
            __props__.__dict__["require_uppercase_characters"] = require_uppercase_characters
        super(Iam, __self__).__init__(
            'securebaseline:index:Iam',
            resource_name,
            __props__,
            opts,
            remote=True)


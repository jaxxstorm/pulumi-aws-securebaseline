// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading.Tasks;
using Pulumi.Serialization;

namespace Pulumi.Securebaseline
{
    [SecurebaselineResourceType("securebaseline:index:Iam")]
    public partial class Iam : Pulumi.ComponentResource
    {
        /// <summary>
        /// Create a Iam resource with the given unique name, arguments, and options.
        /// </summary>
        ///
        /// <param name="name">The unique name of the resource</param>
        /// <param name="args">The arguments used to populate this resource's properties</param>
        /// <param name="options">A bag of options that control this resource's behavior</param>
        public Iam(string name, IamArgs? args = null, ComponentResourceOptions? options = null)
            : base("securebaseline:index:Iam", name, args ?? new IamArgs(), MakeResourceOptions(options, ""), remote: true)
        {
        }

        private static ComponentResourceOptions MakeResourceOptions(ComponentResourceOptions? options, Input<string>? id)
        {
            var defaultOptions = new ComponentResourceOptions
            {
                Version = Utilities.Version,
            };
            var merged = ComponentResourceOptions.Merge(defaultOptions, options);
            // Override the ID if one was specified for consistency with other language SDKs.
            merged.Id = id ?? merged.Id;
            return merged;
        }
    }

    public sealed class IamArgs : Pulumi.ResourceArgs
    {
        [Input("allowUsersToChangePassword")]
        public Input<bool>? AllowUsersToChangePassword { get; set; }

        [Input("enablePasswordPolicy")]
        public Input<bool>? EnablePasswordPolicy { get; set; }

        [Input("enableSupportRole")]
        public Input<bool>? EnableSupportRole { get; set; }

        [Input("minimumPasswordLength")]
        public Input<double>? MinimumPasswordLength { get; set; }

        [Input("passwordReusePrevention")]
        public Input<double>? PasswordReusePrevention { get; set; }

        [Input("requireLowercaseCharacters")]
        public Input<bool>? RequireLowercaseCharacters { get; set; }

        [Input("requireNumbers")]
        public Input<bool>? RequireNumbers { get; set; }

        [Input("requireSymbols")]
        public Input<bool>? RequireSymbols { get; set; }

        [Input("requireUppercaseCharacters")]
        public Input<bool>? RequireUppercaseCharacters { get; set; }

        public IamArgs()
        {
        }
    }
}

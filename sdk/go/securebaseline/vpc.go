// *** WARNING: this file was generated by Pulumi SDK Generator. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package securebaseline

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

type Vpc struct {
	pulumi.ResourceState
}

// NewVpc registers a new resource with the given unique name, arguments, and options.
func NewVpc(ctx *pulumi.Context,
	name string, args *VpcArgs, opts ...pulumi.ResourceOption) (*Vpc, error) {
	if args == nil {
		args = &VpcArgs{}
	}

	var resource Vpc
	err := ctx.RegisterRemoteComponentResource("securebaseline:index:Vpc", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

type vpcArgs struct {
	EnableFlowLogs       *bool    `pulumi:"enableFlowLogs"`
	FlowLogRetentionDays *float64 `pulumi:"flowLogRetentionDays"`
	IamRoleArn           *string  `pulumi:"iamRoleArn"`
	// The additional tags to add.
	Tags map[string]string `pulumi:"tags"`
}

// The set of arguments for constructing a Vpc resource.
type VpcArgs struct {
	EnableFlowLogs       pulumi.BoolPtrInput
	FlowLogRetentionDays pulumi.Float64PtrInput
	IamRoleArn           pulumi.StringPtrInput
	// The additional tags to add.
	Tags pulumi.StringMapInput
}

func (VpcArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*vpcArgs)(nil)).Elem()
}

type VpcInput interface {
	pulumi.Input

	ToVpcOutput() VpcOutput
	ToVpcOutputWithContext(ctx context.Context) VpcOutput
}

func (*Vpc) ElementType() reflect.Type {
	return reflect.TypeOf((**Vpc)(nil)).Elem()
}

func (i *Vpc) ToVpcOutput() VpcOutput {
	return i.ToVpcOutputWithContext(context.Background())
}

func (i *Vpc) ToVpcOutputWithContext(ctx context.Context) VpcOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VpcOutput)
}

// VpcArrayInput is an input type that accepts VpcArray and VpcArrayOutput values.
// You can construct a concrete instance of `VpcArrayInput` via:
//
//          VpcArray{ VpcArgs{...} }
type VpcArrayInput interface {
	pulumi.Input

	ToVpcArrayOutput() VpcArrayOutput
	ToVpcArrayOutputWithContext(context.Context) VpcArrayOutput
}

type VpcArray []VpcInput

func (VpcArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Vpc)(nil)).Elem()
}

func (i VpcArray) ToVpcArrayOutput() VpcArrayOutput {
	return i.ToVpcArrayOutputWithContext(context.Background())
}

func (i VpcArray) ToVpcArrayOutputWithContext(ctx context.Context) VpcArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VpcArrayOutput)
}

// VpcMapInput is an input type that accepts VpcMap and VpcMapOutput values.
// You can construct a concrete instance of `VpcMapInput` via:
//
//          VpcMap{ "key": VpcArgs{...} }
type VpcMapInput interface {
	pulumi.Input

	ToVpcMapOutput() VpcMapOutput
	ToVpcMapOutputWithContext(context.Context) VpcMapOutput
}

type VpcMap map[string]VpcInput

func (VpcMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Vpc)(nil)).Elem()
}

func (i VpcMap) ToVpcMapOutput() VpcMapOutput {
	return i.ToVpcMapOutputWithContext(context.Background())
}

func (i VpcMap) ToVpcMapOutputWithContext(ctx context.Context) VpcMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VpcMapOutput)
}

type VpcOutput struct{ *pulumi.OutputState }

func (VpcOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Vpc)(nil)).Elem()
}

func (o VpcOutput) ToVpcOutput() VpcOutput {
	return o
}

func (o VpcOutput) ToVpcOutputWithContext(ctx context.Context) VpcOutput {
	return o
}

type VpcArrayOutput struct{ *pulumi.OutputState }

func (VpcArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Vpc)(nil)).Elem()
}

func (o VpcArrayOutput) ToVpcArrayOutput() VpcArrayOutput {
	return o
}

func (o VpcArrayOutput) ToVpcArrayOutputWithContext(ctx context.Context) VpcArrayOutput {
	return o
}

func (o VpcArrayOutput) Index(i pulumi.IntInput) VpcOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Vpc {
		return vs[0].([]*Vpc)[vs[1].(int)]
	}).(VpcOutput)
}

type VpcMapOutput struct{ *pulumi.OutputState }

func (VpcMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Vpc)(nil)).Elem()
}

func (o VpcMapOutput) ToVpcMapOutput() VpcMapOutput {
	return o
}

func (o VpcMapOutput) ToVpcMapOutputWithContext(ctx context.Context) VpcMapOutput {
	return o
}

func (o VpcMapOutput) MapIndex(k pulumi.StringInput) VpcOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Vpc {
		return vs[0].(map[string]*Vpc)[vs[1].(string)]
	}).(VpcOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*VpcInput)(nil)).Elem(), &Vpc{})
	pulumi.RegisterInputType(reflect.TypeOf((*VpcArrayInput)(nil)).Elem(), VpcArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*VpcMapInput)(nil)).Elem(), VpcMap{})
	pulumi.RegisterOutputType(VpcOutput{})
	pulumi.RegisterOutputType(VpcArrayOutput{})
	pulumi.RegisterOutputType(VpcMapOutput{})
}
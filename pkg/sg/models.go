package sg

import (
	"github.com/aws/aws-sdk-go/service/ec2"
)

// Tag contains 'key:value' of a single AWS Tag
type Tag struct {
	Key   *string
	Value *string
}

// SecurityGroup represents an Ingress rule
type SecurityGroup struct {
	ID *string
}

// Rule contains an info required for ingress/egress rules
type Rule struct {
	Permissions []*ec2.IpPermission
}

// Client represents an EC2 client
type Client interface {
	AuthorizeSecurityGroupIngress(*ec2.AuthorizeSecurityGroupIngressInput) (*ec2.AuthorizeSecurityGroupIngressOutput, error)
	RevokeSecurityGroupIngress(*ec2.RevokeSecurityGroupIngressInput) (*ec2.RevokeSecurityGroupIngressOutput, error)
	DescribeSecurityGroups(*ec2.DescribeSecurityGroupsInput) (*ec2.DescribeSecurityGroupsOutput, error)
}

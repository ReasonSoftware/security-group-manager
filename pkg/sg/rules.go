package sg

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// AuthorizeIngressRule on a Security Group (receiver)
func (a *SecurityGroup) AuthorizeIngressRule(cli Client, r *Rule) error {
	_, err := cli.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
		DryRun:        aws.Bool(false),
		GroupId:       a.ID,
		IpPermissions: r.Permissions,
	})

	return err
}

// RevokeIngressRule from a Security Group (receiver)
func (a *SecurityGroup) RevokeIngressRule(cli Client, r *Rule) error {
	_, err := cli.RevokeSecurityGroupIngress(&ec2.RevokeSecurityGroupIngressInput{
		DryRun:        aws.Bool(false),
		GroupId:       a.ID,
		IpPermissions: r.Permissions,
	})

	return err
}

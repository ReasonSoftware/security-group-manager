package sg_test

import (
	"errors"
	"testing"

	"github.com/ReasonSoftware/security-group-manager/mocks"
	"github.com/ReasonSoftware/security-group-manager/pkg/sg"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/stretchr/testify/assert"
)

const ID string = "sg-0123a4567bc89defg"

func TestAuthorizeIngressRule(t *testing.T) {
	assert := assert.New(t)

	type test struct {
		Receiver      *sg.SecurityGroup
		Parameter     *sg.Rule
		MockInput     *ec2.AuthorizeSecurityGroupIngressInput
		MockOutput    *ec2.AuthorizeSecurityGroupIngressOutput
		MockError     error
		ExpectedError string
	}

	suite := map[string]test{
		"Success": {
			Receiver: &sg.SecurityGroup{
				ID: aws.String(ID),
			},
			Parameter: &sg.Rule{
				Permissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
						IpProtocol: aws.String("tcp"),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String("owned"),
							},
						},
					},
				},
			},
			MockInput: &ec2.AuthorizeSecurityGroupIngressInput{
				DryRun:  aws.Bool(false),
				GroupId: aws.String(ID),
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
						IpProtocol: aws.String("tcp"),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String("owned"),
							},
						},
					},
				},
			},
			MockOutput:    &ec2.AuthorizeSecurityGroupIngressOutput{},
			MockError:     nil,
			ExpectedError: "",
		},
		"Failure": {
			Receiver: &sg.SecurityGroup{
				ID: aws.String(ID),
			},
			Parameter: &sg.Rule{
				Permissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
						IpProtocol: aws.String("tcp"),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String("owned"),
							},
						},
					},
				},
			},
			MockInput: &ec2.AuthorizeSecurityGroupIngressInput{
				DryRun:  aws.Bool(false),
				GroupId: aws.String(ID),
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
						IpProtocol: aws.String("tcp"),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String("owned"),
							},
						},
					},
				},
			},
			MockOutput:    &ec2.AuthorizeSecurityGroupIngressOutput{},
			MockError:     errors.New("reason"),
			ExpectedError: "reason",
		},
	}

	var counter int
	for name, test := range suite {
		counter++
		t.Logf("Test Case %v/%v - %s", counter, len(suite), name)

		m := new(mocks.SG)

		m.On("AuthorizeSecurityGroupIngress", test.MockInput).Return(test.MockOutput, test.MockError).Once()

		err := test.Receiver.AuthorizeIngressRule(m, test.Parameter)

		if test.ExpectedError != "" {
			assert.EqualError(err, test.ExpectedError)
		} else {
			assert.Equal(nil, err)
		}
	}
}

func TestRevokeIngressRule(t *testing.T) {
	assert := assert.New(t)

	type test struct {
		Receiver      *sg.SecurityGroup
		Parameter     *sg.Rule
		MockInput     *ec2.RevokeSecurityGroupIngressInput
		MockOutput    *ec2.RevokeSecurityGroupIngressOutput
		MockError     error
		ExpectedError string
	}

	suite := map[string]test{
		"Success": {
			Receiver: &sg.SecurityGroup{
				ID: aws.String(ID),
			},
			Parameter: &sg.Rule{
				Permissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
						IpProtocol: aws.String("tcp"),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String("owned"),
							},
						},
					},
				},
			},
			MockInput: &ec2.RevokeSecurityGroupIngressInput{
				DryRun:  aws.Bool(false),
				GroupId: aws.String(ID),
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
						IpProtocol: aws.String("tcp"),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String("owned"),
							},
						},
					},
				},
			},
			MockOutput:    &ec2.RevokeSecurityGroupIngressOutput{},
			MockError:     nil,
			ExpectedError: "",
		},
		"Failure": {
			Receiver: &sg.SecurityGroup{
				ID: aws.String(ID),
			},
			Parameter: &sg.Rule{
				Permissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
						IpProtocol: aws.String("tcp"),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String("owned"),
							},
						},
					},
				},
			},
			MockInput: &ec2.RevokeSecurityGroupIngressInput{
				DryRun:  aws.Bool(false),
				GroupId: aws.String(ID),
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
						IpProtocol: aws.String("tcp"),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String("owned"),
							},
						},
					},
				},
			},
			MockOutput:    &ec2.RevokeSecurityGroupIngressOutput{},
			MockError:     errors.New("reason"),
			ExpectedError: "reason",
		},
	}

	var counter int
	for name, test := range suite {
		counter++
		t.Logf("Test Case %v/%v - %s", counter, len(suite), name)

		m := new(mocks.SG)

		m.On("RevokeSecurityGroupIngress", test.MockInput).Return(test.MockOutput, test.MockError).Once()

		err := test.Receiver.RevokeIngressRule(m, test.Parameter)

		if test.ExpectedError != "" {
			assert.EqualError(err, test.ExpectedError)
		} else {
			assert.Equal(nil, err)
		}
	}
}

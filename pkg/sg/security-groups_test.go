package sg_test

import (
	"testing"

	"github.com/pkg/errors"

	"github.com/ReasonSoftware/security-group-manager/mocks"
	"github.com/ReasonSoftware/security-group-manager/pkg/sg"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/stretchr/testify/assert"
)

func TestGetSecurityGroups(t *testing.T) {
	assert := assert.New(t)

	type test struct {
		Receiver       *sg.Tag
		MockInput1     *ec2.DescribeSecurityGroupsInput
		MockOutput1    *ec2.DescribeSecurityGroupsOutput
		MockInput2     *ec2.DescribeSecurityGroupsInput
		MockOutput2    *ec2.DescribeSecurityGroupsOutput
		MockError      error
		ExpectedError  string
		ExpectedOutput []*ec2.SecurityGroup
	}

	filter := []*ec2.Filter{
		{
			Name:   aws.String("key"),
			Values: []*string{aws.String("value")},
		},
	}

	token := aws.String("token")

	suite := map[string]test{
		"Success": {
			Receiver: &sg.Tag{
				Key:   aws.String("key"),
				Value: aws.String("value"),
			},
			MockInput1: &ec2.DescribeSecurityGroupsInput{
				MaxResults: aws.Int64(100),
				Filters:    filter,
			},
			MockOutput1: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []*ec2.SecurityGroup{
					{
						GroupId: aws.String("sg-1"),
					},
					{
						GroupId: aws.String("sg-2"),
					},
				},
				NextToken: token,
			},
			MockInput2: &ec2.DescribeSecurityGroupsInput{
				MaxResults: aws.Int64(100),
				Filters:    filter,
				NextToken:  token,
			},
			MockOutput2: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []*ec2.SecurityGroup{
					{
						GroupId: aws.String("sg-3"),
					},
				},
				NextToken: nil,
			},
			MockError:     nil,
			ExpectedError: "",
			ExpectedOutput: []*ec2.SecurityGroup{
				{
					GroupId: aws.String("sg-1"),
				},
				{
					GroupId: aws.String("sg-2"),
				},
				{
					GroupId: aws.String("sg-3"),
				},
			},
		},
		"Failure": {
			Receiver: &sg.Tag{
				Key:   aws.String("key"),
				Value: aws.String("value"),
			},
			MockInput1: &ec2.DescribeSecurityGroupsInput{
				MaxResults: aws.Int64(100),
				Filters:    filter,
			},
			MockOutput1:    &ec2.DescribeSecurityGroupsOutput{},
			MockError:      errors.New("reason"),
			ExpectedError:  "reason",
			ExpectedOutput: nil,
		},
		"Single Security Group": {
			Receiver: &sg.Tag{
				Key:   aws.String("key"),
				Value: aws.String("value"),
			},
			MockInput1: &ec2.DescribeSecurityGroupsInput{
				MaxResults: aws.Int64(100),
				Filters:    filter,
			},
			MockOutput1: &ec2.DescribeSecurityGroupsOutput{
				SecurityGroups: []*ec2.SecurityGroup{
					{
						GroupId: aws.String("sg-1"),
					},
				},
				NextToken: nil,
			},
			MockError:     nil,
			ExpectedError: "",
			ExpectedOutput: []*ec2.SecurityGroup{
				{
					GroupId: aws.String("sg-1"),
				},
			},
		},
		"Security Group Not Found": {
			Receiver: &sg.Tag{
				Key:   aws.String("key"),
				Value: aws.String("value"),
			},
			MockInput1: &ec2.DescribeSecurityGroupsInput{
				MaxResults: aws.Int64(100),
				Filters:    filter,
			},
			MockOutput1:    &ec2.DescribeSecurityGroupsOutput{},
			MockError:      nil,
			ExpectedError:  "",
			ExpectedOutput: []*ec2.SecurityGroup{},
		},
	}

	var counter int
	for name, test := range suite {
		counter++
		t.Logf("Test Case %v/%v - %s", counter, len(suite), name)

		m := new(mocks.SG)

		m.On("DescribeSecurityGroups", test.MockInput1).Return(test.MockOutput1, test.MockError).Once()
		if test.MockInput2 != nil {
			m.On("DescribeSecurityGroups", test.MockInput2).Return(test.MockOutput2, test.MockError).Once()
		}

		result, err := test.Receiver.GetSecurityGroups(m)

		if test.ExpectedError != "" {
			assert.EqualError(err, test.ExpectedError)
		} else {
			assert.Equal(nil, err)
		}

		assert.Equal(test.ExpectedOutput, result)
	}
}

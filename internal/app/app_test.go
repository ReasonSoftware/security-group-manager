package app_test

import (
	"testing"

	"github.com/ReasonSoftware/security-group-manager/internal/app"
	"github.com/ReasonSoftware/security-group-manager/mocks"
	"github.com/ReasonSoftware/security-group-manager/pkg/sg"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/stretchr/testify/assert"
)

func TestCategorizeRules(t *testing.T) {
	assert := assert.New(t)

	type test struct {
		Receiver       *app.Config
		Parameter1     *app.Protocol
		Parameter2     []*ec2.IpPermission
		ExpectedOutput *app.Catalog
	}

	suite := map[string]test{
		"Functionality": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: []*ec2.IpPermission{
				{
					IpProtocol: aws.String("tcp"),
					FromPort:   aws.Int64(80),
					ToPort:     aws.Int64(80),
					IpRanges: []*ec2.IpRange{
						{
							CidrIp: aws.String("10.0.0.0/16"),
						},
					},
				},
			},
			ExpectedOutput: &app.Catalog{
				Correct: &app.Group{
					Rules: []*sg.Rule{
						{
							Permissions: []*ec2.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int64(80),
									ToPort:     aws.Int64(80),
									IpRanges: []*ec2.IpRange{
										{
											CidrIp: aws.String("10.0.0.0/16"),
										},
									},
								},
							},
						},
					},
					CIDRs: []string{"10.0.0.0/16"},
				},
				Incorrect: &app.Group{
					Rules: make([]*sg.Rule, 0),
					CIDRs: make([]string, 0),
				},
				Missing: &app.Group{
					Rules: make([]*sg.Rule, 0),
					CIDRs: make([]string, 0),
				},
			},
		},
		"Correct Rule": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: []*ec2.IpPermission{
				{
					IpProtocol: aws.String("tcp"),
					FromPort:   aws.Int64(80),
					ToPort:     aws.Int64(80),
					IpRanges: []*ec2.IpRange{
						{
							CidrIp: aws.String("10.0.0.0/16"),
						},
					},
				},
			},
			ExpectedOutput: &app.Catalog{
				Correct: &app.Group{
					Rules: []*sg.Rule{
						{
							Permissions: []*ec2.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int64(80),
									ToPort:     aws.Int64(80),
									IpRanges: []*ec2.IpRange{
										{
											CidrIp: aws.String("10.0.0.0/16"),
										},
									},
								},
							},
						},
					},
					CIDRs: []string{"10.0.0.0/16"},
				},
				Incorrect: &app.Group{
					Rules: make([]*sg.Rule, 0),
					CIDRs: make([]string, 0),
				},
				Missing: &app.Group{
					Rules: make([]*sg.Rule, 0),
					CIDRs: make([]string, 0),
				},
			},
		},
		"Incorrect Rule": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: []*ec2.IpPermission{
				{
					IpProtocol: aws.String("tcp"),
					FromPort:   aws.Int64(80),
					ToPort:     aws.Int64(80),
					IpRanges: []*ec2.IpRange{
						{
							CidrIp:      aws.String("11.0.0.0/16"),
							Description: aws.String(app.RuleDescription),
						},
					},
				},
			},
			ExpectedOutput: &app.Catalog{
				Correct: &app.Group{
					Rules: make([]*sg.Rule, 0),
					CIDRs: make([]string, 0),
				},
				Incorrect: &app.Group{
					Rules: []*sg.Rule{
						{
							Permissions: []*ec2.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int64(80),
									ToPort:     aws.Int64(80),
									IpRanges: []*ec2.IpRange{
										{
											CidrIp:      aws.String("11.0.0.0/16"),
											Description: aws.String(app.RuleDescription),
										},
									},
								},
							},
						},
					},
					CIDRs: []string{"11.0.0.0/16"},
				},
				Missing: &app.Group{
					Rules: []*sg.Rule{
						{
							Permissions: []*ec2.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int64(80),
									ToPort:     aws.Int64(80),
									IpRanges: []*ec2.IpRange{
										{
											CidrIp:      aws.String("10.0.0.0/16"),
											Description: aws.String(app.RuleDescription),
										},
									},
								},
							},
						},
					},
					CIDRs: []string{"10.0.0.0/16"},
				},
			},
		},
		"Missing Rule": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: []*ec2.IpPermission{},
			ExpectedOutput: &app.Catalog{
				Correct: &app.Group{
					Rules: make([]*sg.Rule, 0),
					CIDRs: make([]string, 0),
				},
				Incorrect: &app.Group{
					Rules: make([]*sg.Rule, 0),
					CIDRs: make([]string, 0),
				},
				Missing: &app.Group{
					Rules: []*sg.Rule{
						{
							Permissions: []*ec2.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int64(80),
									ToPort:     aws.Int64(80),
									IpRanges: []*ec2.IpRange{
										{
											CidrIp:      aws.String("10.0.0.0/16"),
											Description: aws.String(app.RuleDescription),
										},
									},
								},
							},
						},
					},
					CIDRs: []string{"10.0.0.0/16"},
				},
			},
		},
		"Empty Permissions": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: []*ec2.IpPermission{},
			ExpectedOutput: &app.Catalog{
				Correct: &app.Group{
					Rules: make([]*sg.Rule, 0),
					CIDRs: make([]string, 0),
				},
				Incorrect: &app.Group{
					Rules: make([]*sg.Rule, 0),
					CIDRs: make([]string, 0),
				},
				Missing: &app.Group{
					Rules: []*sg.Rule{
						{
							Permissions: []*ec2.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int64(80),
									ToPort:     aws.Int64(80),
									IpRanges: []*ec2.IpRange{
										{
											CidrIp:      aws.String("10.0.0.0/16"),
											Description: aws.String(app.RuleDescription),
										},
									},
								},
							},
						},
					},
					CIDRs: []string{"10.0.0.0/16"},
				},
			},
		},
		"Empty Whitelist": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: []*ec2.IpPermission{
				{
					IpProtocol: aws.String("tcp"),
					FromPort:   aws.Int64(80),
					ToPort:     aws.Int64(80),
					IpRanges: []*ec2.IpRange{
						{
							CidrIp:      aws.String("11.0.0.0/16"),
							Description: aws.String(app.RuleDescription),
						},
					},
				},
			},
			ExpectedOutput: &app.Catalog{
				Correct: &app.Group{
					Rules: make([]*sg.Rule, 0),
					CIDRs: make([]string, 0),
				},
				Incorrect: &app.Group{
					Rules: []*sg.Rule{
						{
							Permissions: []*ec2.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int64(80),
									ToPort:     aws.Int64(80),
									IpRanges: []*ec2.IpRange{
										{
											CidrIp:      aws.String("11.0.0.0/16"),
											Description: aws.String(app.RuleDescription),
										},
									},
								},
							},
						},
					},
					CIDRs: []string{"11.0.0.0/16"},
				},
				Missing: &app.Group{
					Rules: make([]*sg.Rule, 0),
					CIDRs: make([]string, 0),
				},
			},
		},
		"Complex Case": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
					{
						CIDR: aws.String("11.0.0.0/16"),
					},
					{
						CIDR: aws.String("12.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: []*ec2.IpPermission{
				{
					IpProtocol: aws.String("tcp"),
					FromPort:   aws.Int64(80),
					ToPort:     aws.Int64(80),
					IpRanges: []*ec2.IpRange{
						{
							CidrIp: aws.String("10.0.0.0/16"),
						},
					},
				},
				{
					IpProtocol: aws.String("tcp"),
					FromPort:   aws.Int64(80),
					ToPort:     aws.Int64(80),
					IpRanges: []*ec2.IpRange{
						{
							CidrIp: aws.String("20.0.0.0/16"),
						},
					},
				},
			},
			ExpectedOutput: &app.Catalog{
				Correct: &app.Group{
					Rules: []*sg.Rule{
						{
							Permissions: []*ec2.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int64(80),
									ToPort:     aws.Int64(80),
									IpRanges: []*ec2.IpRange{
										{
											CidrIp: aws.String("10.0.0.0/16"),
										},
									},
								},
							},
						},
					},
					CIDRs: []string{"10.0.0.0/16"},
				},
				Incorrect: &app.Group{
					Rules: []*sg.Rule{
						{
							Permissions: []*ec2.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int64(80),
									ToPort:     aws.Int64(80),
									IpRanges: []*ec2.IpRange{
										{
											CidrIp: aws.String("20.0.0.0/16"),
										},
									},
								},
							},
						},
					},
					CIDRs: []string{"20.0.0.0/16"},
				},
				Missing: &app.Group{
					Rules: []*sg.Rule{
						{
							Permissions: []*ec2.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int64(80),
									ToPort:     aws.Int64(80),
									IpRanges: []*ec2.IpRange{
										{
											CidrIp:      aws.String("11.0.0.0/16"),
											Description: aws.String(app.RuleDescription),
										},
									},
								},
							},
						},
						{
							Permissions: []*ec2.IpPermission{
								{
									IpProtocol: aws.String("tcp"),
									FromPort:   aws.Int64(80),
									ToPort:     aws.Int64(80),
									IpRanges: []*ec2.IpRange{
										{
											CidrIp:      aws.String("12.0.0.0/16"),
											Description: aws.String(app.RuleDescription),
										},
									},
								},
							},
						},
					},
					CIDRs: []string{"11.0.0.0/16", "12.0.0.0/16"},
				},
			},
		},
	}

	var counter int
	for name, test := range suite {
		counter++
		t.Logf("Test Case %v/%v - %s", counter, len(suite), name)

		result := app.CategorizeRules(test.Receiver, test.Parameter1, test.Parameter2)

		assert.Equal(test.ExpectedOutput, result)
	}
}

func TestGetManagedRules(t *testing.T) {
	assert := assert.New(t)

	type test struct {
		Receiver        *app.Config
		Parameter1      *app.Protocol
		Parameter2      *ec2.SecurityGroup
		ExpectedOutput1 []*ec2.IpPermission
		ExpectedOutput2 []string
	}

	suite := map[string]test{
		"Functionality": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: &ec2.SecurityGroup{
				IpPermissions: []*ec2.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String(app.RuleDescription),
							},
						},
					},
				},
			},
			ExpectedOutput1: []*ec2.IpPermission{
				{
					FromPort:   aws.Int64(80),
					ToPort:     aws.Int64(80),
					IpProtocol: aws.String("tcp"),
					IpRanges: []*ec2.IpRange{
						{
							CidrIp:      aws.String("10.0.0.0/16"),
							Description: aws.String(app.RuleDescription),
						},
					},
				},
			},
			ExpectedOutput2: []string{
				"10.0.0.0/16",
			},
		},
		"Multiple Different Size Security Groups": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
					{
						CIDR: aws.String("11.0.0.0/16"),
					},
					{
						CIDR: aws.String("12.0.0.0/16"),
					},
					{
						CIDR: aws.String("13.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: &ec2.SecurityGroup{
				IpPermissions: []*ec2.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String(app.RuleDescription),
							},
						},
					},
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("11.0.0.0/16"),
								Description: aws.String(app.RuleDescription),
							},
							{
								CidrIp:      aws.String("12.0.0.0/16"),
								Description: aws.String(app.RuleDescription),
							},
						},
					},
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("13.0.0.0/16"),
								Description: aws.String(app.RuleDescription),
							},
						},
					},
				},
			},
			ExpectedOutput1: []*ec2.IpPermission{
				{
					FromPort:   aws.Int64(80),
					ToPort:     aws.Int64(80),
					IpProtocol: aws.String("tcp"),
					IpRanges: []*ec2.IpRange{
						{
							CidrIp:      aws.String("10.0.0.0/16"),
							Description: aws.String(app.RuleDescription),
						},
					},
				},
				{
					FromPort:   aws.Int64(80),
					ToPort:     aws.Int64(80),
					IpProtocol: aws.String("tcp"),
					IpRanges: []*ec2.IpRange{
						{
							CidrIp:      aws.String("11.0.0.0/16"),
							Description: aws.String(app.RuleDescription),
						},
					},
				},
				{
					FromPort:   aws.Int64(80),
					ToPort:     aws.Int64(80),
					IpProtocol: aws.String("tcp"),
					IpRanges: []*ec2.IpRange{
						{
							CidrIp:      aws.String("12.0.0.0/16"),
							Description: aws.String(app.RuleDescription),
						},
					},
				},
				{
					FromPort:   aws.Int64(80),
					ToPort:     aws.Int64(80),
					IpProtocol: aws.String("tcp"),
					IpRanges: []*ec2.IpRange{
						{
							CidrIp:      aws.String("13.0.0.0/16"),
							Description: aws.String(app.RuleDescription),
						},
					},
				},
			},
			ExpectedOutput2: []string{
				"10.0.0.0/16",
				"11.0.0.0/16",
				"12.0.0.0/16",
				"13.0.0.0/16",
			},
		},
		"Incorrect CIDR": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: &ec2.SecurityGroup{
				IpPermissions: []*ec2.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("11.0.0.0/16"),
								Description: aws.String(app.RuleDescription),
							},
						},
					},
				},
			},
			ExpectedOutput1: []*ec2.IpPermission{
				{
					FromPort:   aws.Int64(80),
					ToPort:     aws.Int64(80),
					IpProtocol: aws.String("tcp"),
					IpRanges: []*ec2.IpRange{
						{
							CidrIp:      aws.String("11.0.0.0/16"),
							Description: aws.String(app.RuleDescription),
						},
					},
				},
			},
			ExpectedOutput2: []string{
				"11.0.0.0/16",
			},
		},
		"Incorrect Transport Protocol": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: &ec2.SecurityGroup{
				IpPermissions: []*ec2.IpPermission{
					{
						IpProtocol: aws.String("udp"),
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String(app.RuleDescription),
							},
						},
					},
				},
			},
			ExpectedOutput1: []*ec2.IpPermission{},
			ExpectedOutput2: []string{},
		},
		"Incorrect ToPort": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: &ec2.SecurityGroup{
				IpPermissions: []*ec2.IpPermission{
					{
						IpProtocol: aws.String("udp"),
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(8080),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String(app.RuleDescription),
							},
						},
					},
				},
			},
			ExpectedOutput1: []*ec2.IpPermission{},
			ExpectedOutput2: []string{},
		},
		"Incorrect FromPort": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: &ec2.SecurityGroup{
				IpPermissions: []*ec2.IpPermission{
					{
						IpProtocol: aws.String("udp"),
						FromPort:   aws.Int64(8080),
						ToPort:     aws.Int64(80),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String(app.RuleDescription),
							},
						},
					},
				},
			},
			ExpectedOutput1: []*ec2.IpPermission{},
			ExpectedOutput2: []string{},
		},
		"Nil Protocol": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: &ec2.SecurityGroup{
				IpPermissions: []*ec2.IpPermission{
					{
						FromPort: aws.Int64(80),
						ToPort:   aws.Int64(80),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String(app.RuleDescription),
							},
						},
					},
				},
			},
			ExpectedOutput1: []*ec2.IpPermission{},
			ExpectedOutput2: []string{},
		},
		"Nil ToPort": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: &ec2.SecurityGroup{
				IpPermissions: []*ec2.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int64(80),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String(app.RuleDescription),
							},
						},
					},
				},
			},
			ExpectedOutput1: []*ec2.IpPermission{},
			ExpectedOutput2: []string{},
		},
		"Nil FromPort": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: &ec2.SecurityGroup{
				IpPermissions: []*ec2.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						ToPort:     aws.Int64(80),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String(app.RuleDescription),
							},
						},
					},
				},
			},
			ExpectedOutput1: []*ec2.IpPermission{},
			ExpectedOutput2: []string{},
		},
		"No IpRanges": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: &ec2.SecurityGroup{
				IpPermissions: []*ec2.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
						IpRanges:   []*ec2.IpRange{},
					},
				},
			},
			ExpectedOutput1: []*ec2.IpPermission{},
			ExpectedOutput2: []string{},
		},
		"Not Managed Rule": {
			Receiver: &app.Config{
				Protocols: map[string]*app.Protocol{
					"http": {
						Transport: aws.String("tcp"),
						FromPort:  aws.Int64(80),
						ToPort:    aws.Int64(80),
					},
				},
				Rules: []*app.Rule{
					{
						CIDR: aws.String("10.0.0.0/16"),
					},
				},
			},
			Parameter1: &app.Protocol{
				Transport: aws.String("tcp"),
				FromPort:  aws.Int64(80),
				ToPort:    aws.Int64(80),
			},
			Parameter2: &ec2.SecurityGroup{
				IpPermissions: []*ec2.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int64(80),
						ToPort:     aws.Int64(80),
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      aws.String("10.0.0.0/16"),
								Description: aws.String("not-managed-rule-description"),
							},
						},
					},
				},
			},
			ExpectedOutput1: []*ec2.IpPermission{},
			ExpectedOutput2: []string{},
		},
	}

	var counter int
	for name, test := range suite {
		counter++
		t.Logf("Test Case %v/%v - %s", counter, len(suite), name)

		m := new(mocks.SG)

		results1, results2 := app.GetManagedRules(test.Receiver, m, test.Parameter1, test.Parameter2)

		assert.Equal(test.ExpectedOutput1, results1)
		assert.Equal(test.ExpectedOutput2, results2)
	}
}

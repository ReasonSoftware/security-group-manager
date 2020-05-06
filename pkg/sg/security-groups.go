package sg

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// GetSecurityGroups returns list of Security Groups matching a Tag (receiver)
func (t *Tag) GetSecurityGroups(cli Client) ([]*ec2.SecurityGroup, error) {
	l := []*ec2.SecurityGroup{}
	var token *string

	for {
		o, err := cli.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
			MaxResults: aws.Int64(100),
			Filters: []*ec2.Filter{
				{
					Name:   t.Key,
					Values: []*string{t.Value},
				},
			},
			NextToken: token,
		})
		if err != nil {
			return nil, err
		}

		l = append(l, o.SecurityGroups...)

		if o.NextToken != nil {
			token = o.NextToken
		} else {
			break
		}
	}

	return l, nil
}

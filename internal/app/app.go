package app

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/pkg/errors"
	logger "github.com/sirupsen/logrus"

	"github.com/ReasonSoftware/security-group-manager/pkg/sg"
)

// Version contains current application version
const Version string = "1.1.4"

// Catalog contains rule groups by types
type Catalog struct {
	Correct   *Group
	Incorrect *Group
	Missing   *Group
}

// Group contains similar types of rules
type Group struct {
	Rules []*sg.Rule
	CIDRs []string
}

// Run is a main thread of this application
func (c *Config) Run(cli sg.Client) error {
	for name, protocol := range c.Protocols {
		groups, err := c.fetch(cli, name)
		if err != nil {
			return err
		}

		for _, group := range groups {
			log := logger.WithFields(logger.Fields{
				"security-group": *group.GroupId,
				"rule":           name,
			})

			err := c.manage(cli, log, name, protocol, group)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (c *Config) fetch(cli sg.Client, name string) ([]*ec2.SecurityGroup, error) {
	logger.Infof("fetching security groups with tag: '%s=%s'", name, TagProtocolValue)

	tag := sg.Tag{
		Key:   aws.String(fmt.Sprintf("tag:%s", name)),
		Value: aws.String(TagProtocolValue),
	}

	groups, err := tag.GetSecurityGroups(cli)
	if err != nil {
		return []*ec2.SecurityGroup{}, err
	}

	var list []string

	for _, group := range groups {
		list = append(list, *group.GroupId)
	}

	logger.Infof("found %s matching security groups: %+v", strconv.Itoa(len(list)), list)

	return groups, nil
}

func (c *Config) manage(cli sg.Client, log *logger.Entry, name string, proto *Protocol, target *ec2.SecurityGroup) error {
	log.Infof("validating rules with 'description=%s'", RuleDescription)

	rules, matchedRules := c.getManagedRules(cli, proto, target)
	log.Debugf("found %s matching rules: %+v", strconv.Itoa(len(rules)), matchedRules)

	groups := c.categorizeRules(proto, rules)
	log.Debugf("cidr validation results: correct=%s, incorrect=%s, missing=%s", groups.Correct.CIDRs, groups.Incorrect.CIDRs, groups.Missing.CIDRs)

	securityGroup := &sg.SecurityGroup{
		ID: target.GroupId,
	}

	for _, rule := range groups.Incorrect.Rules {
		log.Infof("removing incorrect cidr: '%s'", *rule.Permissions[0].IpRanges[0].CidrIp)
		if err := securityGroup.RevokeIngressRule(cli, rule); err != nil {
			log.Fatal(errors.Wrap(err, fmt.Sprintf("error removing a cidr '%s' from a security group", *rule.Permissions[0].IpRanges[0].CidrIp)))
		}
	}

	for _, rule := range groups.Missing.Rules {
		log.Infof("adding missing cidr: '%s'", *rule.Permissions[0].IpRanges[0].CidrIp)
		err := securityGroup.AuthorizeIngressRule(cli, rule)
		if err != nil && strings.Contains(err.Error(), "already exists") {
			log.Errorf("duplicate error: cidr '%s' already exist as a not managed rule on requested security group", *rule.Permissions[0].IpRanges[0].CidrIp)
		} else if err != nil {
			if strings.Contains(err.Error(), "RulesPerSecurityGroupLimitExceeded") {
				log.Error("the maximum number of rules per security group has been reached")
				break
			} else {
				log.Fatal(errors.Wrap(err, fmt.Sprintf("error adding a cidr '%s' to a security group", *rule.Permissions[0].IpRanges[0].CidrIp)))
			}
		}
	}

	return nil
}

func (c *Config) getManagedRules(cli sg.Client, proto *Protocol, sg *ec2.SecurityGroup) ([]*ec2.IpPermission, []string) {
	rules := make([]*ec2.IpPermission, 0)
	cidrs := make([]string, 0)

	for _, permission := range sg.IpPermissions {
		if permission.FromPort == nil || permission.ToPort == nil || permission.IpProtocol == nil {
			continue
		}

		equalPorts := *permission.FromPort == *proto.FromPort && *permission.ToPort == *proto.ToPort
		equalProtocol := *permission.IpProtocol == *proto.Transport

		if equalPorts && equalProtocol {
			for _, ipRange := range permission.IpRanges {
				if ipRange.Description != nil && *ipRange.Description == RuleDescription {
					rule := &ec2.IpPermission{
						FromPort:   permission.FromPort,
						ToPort:     permission.ToPort,
						IpProtocol: permission.IpProtocol,
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      ipRange.CidrIp,
								Description: ipRange.Description,
							},
						},
					}

					rules = append(rules, rule)
					cidrs = append(cidrs, *ipRange.CidrIp)
				}
			}
		}
	}

	return rules, cidrs
}

func (c *Config) categorizeRules(proto *Protocol, permissions []*ec2.IpPermission) *Catalog {
	groups := Catalog{
		Correct: &Group{
			Rules: make([]*sg.Rule, 0),
			CIDRs: make([]string, 0),
		},
		Incorrect: &Group{
			Rules: make([]*sg.Rule, 0),
			CIDRs: make([]string, 0),
		},
		Missing: &Group{
			Rules: make([]*sg.Rule, 0),
			CIDRs: make([]string, 0),
		},
	}

	valid := make(map[string]*ec2.IpPermission)

	for _, rule := range c.Rules {
		for _, permission := range permissions {
			if *permission.IpRanges[0].CidrIp == *rule.CIDR {
				valid[*permission.IpRanges[0].CidrIp] = permission

				r := &sg.Rule{
					Permissions: []*ec2.IpPermission{permission},
				}

				groups.Correct.Rules = append(groups.Correct.Rules, r)
				groups.Correct.CIDRs = append(groups.Correct.CIDRs, *permission.IpRanges[0].CidrIp)
			}
		}
	}

	for _, permission := range permissions {
		if valid[*permission.IpRanges[0].CidrIp] == nil {
			r := &sg.Rule{
				Permissions: []*ec2.IpPermission{permission},
			}

			groups.Incorrect.Rules = append(groups.Incorrect.Rules, r)
			groups.Incorrect.CIDRs = append(groups.Incorrect.CIDRs, *permission.IpRanges[0].CidrIp)
		}
	}

	for _, rule := range c.Rules {
		if valid[*rule.CIDR] == nil {
			r := &sg.Rule{
				Permissions: []*ec2.IpPermission{
					{
						FromPort:   proto.FromPort,
						ToPort:     proto.ToPort,
						IpProtocol: proto.Transport,
						IpRanges: []*ec2.IpRange{
							{
								CidrIp:      rule.CIDR,
								Description: aws.String(RuleDescription),
							},
						},
					},
				},
			}

			groups.Missing.Rules = append(groups.Missing.Rules, r)
			groups.Missing.CIDRs = append(groups.Missing.CIDRs, *rule.CIDR)
		}
	}

	return &groups
}

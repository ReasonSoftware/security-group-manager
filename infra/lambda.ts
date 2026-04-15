/// <reference path="../.sst/platform/config.d.ts" />

import { REPO_URL } from "./constants";

export function createFunction() {
  const identity = aws.getCallerIdentityOutput();
  const region = aws.getRegionOutput();

  const fn = new sst.aws.Function("security-group-manager", {
    handler: ".",
    runtime: "go" as const,
    architecture: "arm64" as const,
    timeout: "240 seconds" as const,
    memory: "128 MB" as const,
    logging: {
      retention: "1 month" as const,
    },
    name: "security-group-manager",
    description: `Maintains whitelist rules on EC2 Security Groups. Repo: ${REPO_URL}`,
    environment: {
      SECRET: "whitelist",
      SECRET_REGION: "us-east-1",
      OPERATIONAL_REGION: region.name,
    },
    permissions: [
      {
        actions: ["secretsmanager:GetSecretValue"],
        resources: [
          $interpolate`arn:aws:secretsmanager:us-east-1:${identity.accountId}:secret:whitelist-*`,
        ],
      },
      {
        actions: [
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
        ],
        resources: [
          $interpolate`arn:aws:ec2:${region.name}:${identity.accountId}:security-group/*`,
        ],
      },
      {
        actions: ["ec2:DescribeSecurityGroups"],
        resources: ["*"],
      },
    ],
  });

  return { fn };
}

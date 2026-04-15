/// <reference path="../.sst/platform/config.d.ts" />

import { REPO_URL } from "./constants";

export function createFunction({ secretValues }: {
  secretValues: $util.Output<string>;
}) {
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
      CONFIG: secretValues,
      OPERATIONAL_REGION: region.name,
      SECRET_REGION: "us-east-1",
    },
    permissions: [
      {
        actions: [
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
        ],
        resources: ["arn:aws:ec2:*:*:security-group/*"],
      },
      {
        actions: ["ec2:DescribeSecurityGroups"],
        resources: ["*"],
      },
    ],
  });

  return { fn };
}

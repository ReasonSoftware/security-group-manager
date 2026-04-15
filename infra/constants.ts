/// <reference path="../.sst/platform/config.d.ts" />

const identity = aws.getCallerIdentityOutput();
const region = aws.getRegionOutput();

export const SNS_TOPIC_ARN = $interpolate`arn:aws:sns:${region.name}:${identity.accountId}:devops-alerts-aws-chatbot`;
export const REPO_URL = "https://github.com/ReasonSoftware/security-group-manager";

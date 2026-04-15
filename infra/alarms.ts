/// <reference path="../.sst/platform/config.d.ts" />

import { SNS_TOPIC_ARN } from "./constants";

export function createAlarms({ fn }: { fn: sst.aws.Function }) {
  new aws.cloudwatch.MetricAlarm("security-group-manager-errors", {
    name: "security-group-manager-errors",
    namespace: "AWS/Lambda",
    metricName: "Errors",
    dimensions: { FunctionName: fn.name },
    statistic: "Sum",
    period: 86400,
    evaluationPeriods: 1,
    threshold: 0,
    comparisonOperator: "GreaterThanThreshold",
    treatMissingData: "notBreaching",
    alarmActions: [SNS_TOPIC_ARN],
    okActions: [SNS_TOPIC_ARN],
  });

  new aws.cloudwatch.MetricAlarm("security-group-manager-throttles", {
    name: "security-group-manager-throttles",
    namespace: "AWS/Lambda",
    metricName: "Throttles",
    dimensions: { FunctionName: fn.name },
    statistic: "Sum",
    period: 60,
    evaluationPeriods: 2,
    threshold: 0,
    comparisonOperator: "GreaterThanThreshold",
    treatMissingData: "notBreaching",
    alarmActions: [SNS_TOPIC_ARN],
    okActions: [SNS_TOPIC_ARN],
  });
}

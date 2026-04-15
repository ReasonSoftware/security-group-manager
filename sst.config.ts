/// <reference path="./.sst/platform/config.d.ts" />

// Stage-to-region mapping. The whitelist secret always lives in us-east-1
// (single source of truth), but the Lambda is deployed to the target region
// where it manages security groups.
const STAGE_REGIONS: Record<string, "us-east-1" | "us-west-2"> = {
  "us-east-1": "us-east-1",
  "us-west-2": "us-west-2",
  production: "us-east-1",
};

export default $config({
  app(input) {
    const region = STAGE_REGIONS[input?.stage ?? ""] ?? "us-east-1";

    const isKnownStage = Object.keys(STAGE_REGIONS).includes(input?.stage ?? "");

    return {
      name: "security-group-manager",
      removal: isKnownStage ? "retain" : "remove",
      protect: isKnownStage,
      home: "aws",
      providers: {
        aws: {
          region,
          defaultTags: {
            tags: {
              Name: "security-group-manager",
              iac: "true",
              project: "security-group-manager",
              repository: "security-group-manager",
              team: "devops",
              environment: input?.stage || "dev",
              terraform: "false",
            },
          },
        },
      },
    };
  },
  async run() {
    const { createFunction } = await import("./infra/lambda");
    const { createAlarms } = await import("./infra/alarms");
    const { createCron } = await import("./infra/cron");

    const { fn } = createFunction();
    createAlarms({ fn });
    createCron({ fn });
  },
});

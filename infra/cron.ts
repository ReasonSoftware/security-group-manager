/// <reference path="../.sst/platform/config.d.ts" />

export function createCron({ fn }: { fn: sst.aws.Function }) {
  new sst.aws.Cron("security-group-manager-schedule", {
    schedule: "cron(0/30 * * * ? *)",
    job: fn,
  });
}

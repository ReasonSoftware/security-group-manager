/// <reference path="../.sst/platform/config.d.ts" />

// The whitelist secret is the single source of truth and always lives in
// us-east-1, regardless of which region the Lambda is deployed to.
// We create a dedicated us-east-1 provider to read it, so deployments to
// us-west-2 can still resolve the same secret at deploy time.
export function fetchSecrets() {
  const usEast1 = new aws.Provider("aws-us-east-1", { region: "us-east-1" });

  const secrets = aws.secretsmanager.getSecretVersionOutput(
    { secretId: "whitelist" },
    { provider: usEast1 },
  );

  return { secretValues: secrets.secretString };
}

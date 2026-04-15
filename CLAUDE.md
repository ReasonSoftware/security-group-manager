# Security Group Manager

Go Lambda that maintains whitelist rules on EC2 Security Groups automatically. Uses SST v3 (Ion) with Pulumi.

## Architecture

- **Purpose**: Reconciles IP whitelist rules on Security Groups tagged with `<protocol>=managed`
- **Source of truth**: AWS Secrets Manager secret `whitelist` (in us-east-1) containing `protocols` map and `rules` array of CIDRs
- **Rule ownership**: Only touches ingress rules with description `"owned"` — safe coexistence with manually-added rules
- **Multi-region**: Deployed to both us-east-1 and us-west-2, each managing SGs in its own region. Both regions share the same whitelist secret from us-east-1.

## Project Structure

- `main.go` — Lambda handler entry point (handler signature: `func(context.Context) error`)
- `internal/app/` — Core reconciliation logic
- `pkg/sg/` — Security Group wrapper types and helpers
- `mocks/` — Mock implementations for tests
- `sst.config.ts` — SST infrastructure config with stage-to-region mapping
- `infra/` — Infrastructure components (lambda, alarms, cron, secrets, constants)
- `Makefile` — build targets: test, lint, vendor, run, codecov
- `.golangci.yml` — linter configuration

## Commands

```bash
make test     # run tests with race detector and coverage
make lint     # golangci-lint (requires: go mod vendor first)
make vendor   # vendor dependencies
make run      # run locally with AWS_PROFILE=reason
make codecov  # open coverage report in browser
```

## Conventions

- Version is stored as `Version string` constant in `internal/app/app.go`
- Lambda detection: checks `AWS_LAMBDA_FUNCTION_NAME` env var
- Logging: logrus with JSON formatter, no timestamps (CloudWatch adds them)
- Architecture: arm64 (Graviton) for cost savings
- Environment variables (injected from Secrets Manager at deploy time):
  - `CONFIG` — full whitelist config JSON
  - `OPERATIONAL_REGION` — target region for SG management (set per-deployment)
  - `SECRET_REGION` — region where `whitelist` secret lives (always `us-east-1`)

## Deployment

```bash
sst deploy --stage us-east-1    # Deploy Lambda to us-east-1
sst deploy --stage us-west-2    # Deploy Lambda to us-west-2
```

Both deployments read the same `whitelist` secret from us-east-1 via a cross-region Pulumi Provider.

## Release Workflow

1. Add entries under `## [Unreleased]` in CHANGELOG.md (keepachangelog format with brackets)
2. Commit and push to master
3. Trigger `version.yml` workflow: `gh workflow run version.yml -f version=vX.Y.Z`
4. Workflow updates `internal/app/app.go` version, renames `[Unreleased]` → `[X.Y.Z] - YYYY-MM-DD`, tags and pushes
5. Tag push triggers `release.yml` which creates a GitHub release
6. **Pull locally after version release** — the version workflow pushes commits: `git pull`

## SST Notes

- `sst.config.ts` is always TypeScript regardless of Lambda runtime
- `sst deploy --stage <region>` deploys to the mapped region
- `.sst/` directory is gitignored — generated on `sst dev`/`sst deploy`

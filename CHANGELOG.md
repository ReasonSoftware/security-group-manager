## [2.0.0] - 2026-04-15

### Changed

- Migrate from Serverless Framework to SST v3 (Ion)
- Upgrade Go to 1.24 and switch runtime from `go1.x` to `provided.al2023` (arm64)
- Replace stdlib/text-formatted logrus with JSON-structured logrus logging
- Use `AWS_LAMBDA_FUNCTION_NAME` for Lambda detection instead of `LOCAL` env var
- Handler now accepts `context.Context` and returns `error`
- Keep runtime Secrets Manager fetch on every invocation so whitelist changes propagate within one cron cycle (30 min) without requiring a redeploy
- Stage-based multi-region deployment (`sst deploy --stage us-east-1` / `--stage us-west-2`)
- Add `.golangci.yml` linter configuration
- Add `.editorconfig` for consistent formatting
- Add CloudWatch alarms for errors and throttles via Pulumi
- Add EventBridge cron schedule via `sst.aws.Cron`

### Fixed

- Replace `log.Fatal` in `app.go` with `return errors.Wrap` so EC2 errors propagate to Lambda runtime (enables proper CloudWatch Errors tracking)
- Nil-check `o.SecretString` before dereference (prevents panic on binary-secret edge case)
- Tighten IAM: scope Secrets Manager ARN to current account, scope EC2 ARN to current account + region
- Fix errors alarm period from 86400s (1 day) to 60s so failures page within minutes, not the next day
- `removal: retain` and `protect` now apply to `us-east-1` / `us-west-2` stages (not just `production`) so `sst remove --stage us-east-1` cannot accidentally nuke prod
- Restore test cases for malformed secrets and invalid JSON (dropped during earlier refactor)
- Validate version format in `version.yml` workflow before `sed` interpolation; stage specific files instead of `git add .`

### Removed

- `serverless.yaml` (replaced by `sst.config.ts` and `infra/` directory)

## [1.1.4] - 2021-07-05
### Changed
- Upgrade dependencies

## [1.1.3] - 2021-06-02
### Changed
- Upgrade dependencies

## [1.1.2] - 2021-05-01
### Changed
- Upgrade dependencies

## [1.1.1] - 2021-01-05
### Changed
- Upgrade dependencies
- When maximum number of rules per security group has been reached, produce an error log and continue to other security groups

## [1.1.0] - 2021-01-05
### Added
- Variable `OPERATIONAL_REGION` to contain an AWS region with a target Security Group
- Variable `SECRET_REGION` to contain an AWS region with a source **whitelist** Secret (*Secrets Manager*)

## [1.0.2] - 2021-01-03
### Changed
- Upgrade dependencies

## [1.0.1] - 2020-10-11
### Changed
- Upgrade GoLang to 1.15
- Upgrade dependencies

## [1.0.0] - 2020-05-06
- First release.

[1.1.4]: https://github.com/ReasonSoftware/security-group-manager/compare/v1.1.3...v1.1.4
[1.1.3]: https://github.com/ReasonSoftware/security-group-manager/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/ReasonSoftware/security-group-manager/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/ReasonSoftware/security-group-manager/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/ReasonSoftware/security-group-manager/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/ReasonSoftware/security-group-manager/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/ReasonSoftware/security-group-manager/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/ReasonSoftware/security-group-manager/releases/tag/v1.0.0

# AWS Emulator image

A project-agnostic Docker image of [AWS Emulator](https://docs.aws.amazon.com/emulator/),
AWS's local emulator of AWS service APIs, so any project can run integration tests
against DynamoDB, Cognito, SNS, … without an AWS account.

AWS publishes no prebuilt image and the emulator runs natively on Linux only, so on
macOS (and in CI) it runs from this image, built off the official Linux package.

## Targets

| Command        | What it does                                                                  |
| -------------- | ----------------------------------------------------------------------------- |
| `make update`  | Rebuilds only if GitHub has a newer release than the installed image.         |
| `make build`   | Always rebuilds from the latest package.                                      |
| `make version` | Prints the installed emulator version.                                        |
| `make clean`   | Removes the image, any leftover build of it, and its build cache.             |

The image is tagged `aws-emulator` and is ~1.4 GB. Every build removes the image it
replaces, prunes leftover untagged builds (they carry the `eu.isnan.aws-emulator`
label) and the stale build-cache record of the install step, so rebuilds keep Docker's
disk usage flat and never touch other images or build cache.

The package is deliberately **not pinned**: AWS ships security fixes and new API
coverage only in the latest release.

## Running it from a project

Each project runs the shared image with its own container name, port and state folder:

```sh
mkdir -p .aws-emulator
docker run -d --name myapp-aws-emulator \
  --cap-drop ALL --security-opt no-new-privileges --read-only \
  -e EMULATOR_TELEMETRY=off \
  -p 127.0.0.1:9297:9297 \
  -v "$PWD/.aws-emulator:/home/emulator/.aws/emulator" \
  aws-emulator -p 9297 --idle-timeout 1800
```

- **Loopback only**: publish on `127.0.0.1`, never on all interfaces.
- **Telemetry** is on by default; `EMULATOR_TELEMETRY=off` turns it off.
- **Mount the parent folder** `/home/emulator/.aws/emulator`, not the per-port folder:
  the emulator restricts the port folder to mode 700 at start, which fails on a Docker
  Desktop bind-mount root with `Operation not permitted`.
- The emulator writes this run's `config`, `emulator_credentials` and `ca.pem` to
  `.aws-emulator/<port>/` (regenerated each start: gitignore it). Point clients at it:

  ```sh
  export AWS_ENDPOINT_URL=https://127.0.0.1:9297
  export AWS_SHARED_CREDENTIALS_FILE=$PWD/.aws-emulator/9297/emulator_credentials
  export AWS_CONFIG_FILE=$PWD/.aws-emulator/9297/config
  export AWS_CA_BUNDLE=$PWD/.aws-emulator/9297/ca.pem   # the config's ca_bundle is a container path
  export AWS_EC2_METADATA_DISABLED=true
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_ACCOUNT_ID
  aws sts get-caller-identity   # must report account 000000000000
  ```

  Environment credentials win over the credentials file, so real ones must be unset.
- State is in memory only: `docker stop` drops everything (and deletes the per-run files).
- The emulator never denies a request signed with its own keys: it cannot test IAM
  policies.

`meal-planner` (`packages/functions/Makefile`, `test-integration`) is a working example.

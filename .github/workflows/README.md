# GitHub Actions workflows

The workflows are organized by the event that starts them. Build, test, and
release implementations are kept in reusable workflows so that the entry
workflows contain only orchestration.

## Entry workflows

### `ci.yml` — continuous integration

Runs for open pull requests, pushes to `main`, and merge groups. It calls the
reusable unit-test, lint, and build workflows. Merge groups additionally run the
stable, testing, and oldstable container compatibility builds.

`Merge gate` is the single aggregate job intended for branch protection. On a
pull request it requires tests, linting, and builds. In the merge queue it also
requires all container compatibility builds.

### `container.yml` — container publishing

Runs on pushes to `main`, version tags, the weekly schedule, repository
dispatches, or manual dispatch. It initializes the version and calls
`push-container.yml` to build and publish the stable, testing, and oldstable
multi-architecture images.

Container publishing is deliberately separate from pull-request validation.

### `release.yml` — release orchestration

Runs manually with an explicit major, minor, or patch choice. It also preserves
the existing release-label behavior for merged pull requests:

- `major_release`
- `minor_release`
- `patch_release`

The workflow calculates the version, builds both architecture-qualified Rust
artifacts, and calls `create-release.yml`.

### Other entry workflows

- `auto_label.yml`: labels pull requests from conventional commits.
- `codeql.yml`: analyzes the C code on pull requests, main, and weekly.
- `dependency-review.yml`: reviews dependency changes on pull requests.
- `detect-hidden-unicode.yml`: checks pull requests for hidden Unicode.
- `docs.yml`: checks Markdown links when documentation changes.
- `integration-build.yml`: runs the weekly/manual Bookworm integration build.
- `package-build-on-release.yml`: triggers downstream packaging after a release.
- `sbom-upload.yml`: uploads the SBOM on main or by manual dispatch.

## Reusable workflows

- `init.yaml`: calculates refs, versions, and container-tag properties.
- `tests.yml`: runs C, Rust, and Compose-dependent Rust tests.
- `linting.yml`: runs C/Rust formatting, Clippy, typos, and license checks.
- `build.yml`: builds C and calls the AMD64 and ARM64 Rust binary builder.
- `rust-binaries.yaml`: builds `openvasd` and `scannerctl` for one architecture.
- `container-compatibility.yml`: build-only validation of the three container
  variants on AMD64.
- `push-container.yml`: publishes the three multi-architecture container
  variants and performs registry follow-up work.
- `create-release.yml`: creates, signs, and uploads a GitHub release.

## Required check

Configure repository rules to require only `Merge gate`. Keep the `CI` workflow
and `Merge gate` job names stable because GitHub identifies required checks by
their displayed names.

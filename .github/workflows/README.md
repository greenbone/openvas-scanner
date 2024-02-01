# Continuous Integration Workflow Documentation

This document outlines the Continuous Integration (CI) pipeline, detailing how to trigger releases and the specific roles of various jobs within the workflow.

## Release Trigger Process

To initiate a release, navigate to `Actions -> CI` in the GitHub repository, and click on `Run workflow`. Choose from the following options:
- `major`: For a major release with incompatible changes.
- `minor`: For a minor release introducing new features.
- `patch`: For a patch release focusing on bug fixes and minor improvements.
- `no_release`: To run the pipeline without releasing, updating the edge image.

## Jobs Overview

The CI pipeline incorporates multiple jobs, each with a specific function in the development lifecycle.

### 1. Initialization (`init`)

If the initialization fails it will prevent further execution of `build`.

- **Purpose**: Sets the release type based on the input or event that triggered the workflow.
- **Workflow File**: `init.yaml`

### 2. Unit Tests (`unittests`)
- **Purpose**: Executes unit tests to validate code changes.
- **Workflow File**: `tests.yml`

If the unit tests fails it will prevent further execution of `build`.

### 3. Build (`build`)
- **Purpose**: Compiles and builds the project, preparing it for testing and deployment.
- **Dependencies**: Requires successful completion of `unittests`.
- **Workflow File**: `build.yml`


If the build fails it will prevent further execution of `functional`.

### 4. Linting (`linting`)
- **Purpose**: Ensures code quality and consistency through linting.
- **Workflow File**: `linting.yml`

If linting fails it will not prevent execution of the other steps, as it may be that newer versions of the used tooling finds new linting issues that are not affecting the binary as much.


### 5. Functional Testing (`functional`)
- **Purpose**: Conducts functional tests on the build.
- **Dependencies**: Needs a successful `build`.
- **Workflow File**: `functional.yaml`

If the functional tests fail it will prevent further execution of `containerization`.

### 6. Containerization
- **Purpose**: Packages the build into Docker containers.
- **Jobs**:
  - **Container**: Uses `push-container.yml`.
  - **Container Testing**: Uses `push-container-testing.yml`.
  - **Container Oldstable**: Uses `push-container-oldstable.yml`.
- **Dependencies**: Depends on `build`, `init`, and `functional`.

If the `containerization` fails the smoketests cannot be executed. 

### 7. Smoke Tests (`smoketests`)
- **Purpose**: Conducts tests on helm chart based on the previously pushed docker image.
- **Conditions**: Excluded during pull request events.
- **Dependencies**: Relies on `container`, `build`, and `init`.
- **Workflow File**: `smoketest.yaml`

If the smoketests fail the helm chart will not be updated and releases be prevented.


### 8. Helm Chart Deployment (`helm`)
- **Purpose**: Deploys Helm chart, assuming `IMAGE_REGISTRY` is configured.
- **Conditions**: Triggered if `IMAGE_REGISTRY` is set.
- **Dependencies**: Depends on `smoketests`, `container`, `build`, and `init`.
- **Workflow File**: `push-helm-chart.yml`

### 9. Release (`release`)
- **Purpose**: Handles the release process for different version types.
- **Conditions**: Activated based on the release type set in `init`.
- **Dependencies**: Requires `smoketests`, `container`, `build`, and `init`.
- **Workflow File**: `release.yml`

## Secrets and Authentication

The CI workflow employs GitHub secrets for secure authentication and interaction with external services such as DockerHub.

### Utilized Secrets
- **DOCKERHUB_USERNAME**: DockerHub username.
- **DOCKERHUB_TOKEN**: Token for DockerHub with write access to the registry.
- **GREENBONE_BOT_TOKEN**: Token for Helm chart registry and GitHub repository operations.
- **GREENBONE_BOT**: Username for git commits.
- **GREENBONE_BOT_MAIL**: Email address for git commits.

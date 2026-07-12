#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<'EOF'
Usage: ./check.sh [-v|--verbose] <target>

Options:
  -v, --verbose
              Print versions of tools used by the selected target.

Targets:
  fmt         Run formatting checks.
  fmt-rust    Run Rust formatting checks.
  fmt-c       Run C formatting checks.
  lint-rust   Run Rust formatting and clippy checks.
  lint-c      Run C formatting checks.
  typos       Run spelling checks.
  lychee      Run offline Markdown link checks.
  license-headers
              Run license header checks.
  lint        Run all lint checks.
  audit-rust  Run cargo-audit to check for known vulnerabilities in Rust dependencies.
  ci-build-c  Build C scanner targets in the CI environment.
  ci-codeql-build-c
              Build C scanner targets for CodeQL.
  ci-railguard
              Build and verify a railguard image. Requires RAILGUARD_SYSTEM.
  ci-smokey   Run compose smoketests. Requires OPENVAS_IMAGE.
  ci-feed-syntax
              Run scannerctl feed syntax checks.
  ci-nasl-tests
              Run NASL make check tests.
  ci-nasl-lint
              Run openvas-nasl-lint smoketest.
  test-rust   Run Rust unit tests.
  test-c      Run C unit tests.
  test        Run all tests.
  local       Run locally useful checks, fastest first.

EOF
}

verbose() {
    [[ "${VERBOSE:-0}" == "1" ]]
}

version_command() {
    if verbose; then
        run "$@"
    fi
}

fmt_rust() {
    cd "$ROOT/rust"
    version_command cargo --version
    run cargo fmt --check
}

fmt_c() {
    cd "$ROOT"
    version_command clang-format --version
    mapfile -d '' files < <(git ls-files -z -- '*.c' '*.h' ':(exclude).docker/**')
    if ((${#files[@]} == 0)); then
        return 0
    fi
    run clang-format --dry-run --Werror -style=file "${files[@]}"
}

run() {
    printf 'Running command:'
    printf ' %q' "$@"
    printf '\n'
    "$@"
}

lint_rust() {
    cd "$ROOT/rust"
    version_command cargo --version
    version_command cargo clippy -V
    run make
    run cargo fmt --check
    run cargo clippy --all-targets -- -D warnings --no-deps
    run cargo clippy --all-targets --features native-rust-ssh -- -D warnings --no-deps
}

lint_c() {
    fmt_c
}

typos_check() {
    cd "$ROOT/rust"
    version_command typos --version
    run typos
}

lychee_check() {
    cd "$ROOT"
    version_command lychee --version
    run lychee --files-from <(git ls-files '*.md' ':!.*') --offline --include-fragments --no-progress
}

license_headers() {
    cd "$ROOT"
    local ext f header failed=0
    for ext in c h nasl cmake; do
        while IFS= read -r -d '' f; do
            header="$(head -n 3 "$f")"
            if [[ ! "$header" =~ SPDX ]]; then
                echo "File does not contain license header: $f"
                failed=1
            fi
        done < <(
            find . \
                -not -path "./.docker/*" \
                -not -path "./build/*" \
                -not -path "./rust/target/*" \
                -not -path "./rust/crates/nasl-c-lib/*" \
                -regex ".*\.\($ext\)" \
                -print0
        )
    done
    return "$failed"
}

lint_all() {
    lint_rust
    lint_c
    typos_check
    license_headers
}

audit_rust() {
    cd "$ROOT/rust"
    version_command cargo --version
    if ! command -v cargo-audit &>/dev/null; then
        echo "cargo-audit not found. Install with: cargo install cargo-audit"
        return 1
    fi
    run cargo audit
}

ci_build_c() {
    cd "$ROOT"
    version_command cmake --version
    run cmake -Bbuild/c -DCMAKE_C_COMPILER=/usr/share/clang/scan-build-19/libexec/ccc-analyzer
    run cmake --build build/c
}

ci_codeql_build_c() {
    cd "$ROOT"
    version_command cmake --version
    run cmake -Bbuild/codeql -DCMAKE_BUILD_TYPE=Release
    run cmake --build build/codeql --target install
}

test_rust() {
    cd "$ROOT/rust"
    version_command cargo --version
    run make
    run sh -c 'cd crates/rpmdb-rs && sh prepare-test-data.sh'
    run cargo test --lib --tests --workspace
    run cargo test --lib --tests --workspace --features native-rust-ssh
}

test_c() {
    cd "$ROOT"
    version_command cmake --version
    run cmake -Bbuild/test-c -DCMAKE_BUILD_TYPE=Release
    run env CTEST_OUTPUT_ON_FAILURE=1 cmake --build build/test-c -- tests test
}

test_all() {
    test_rust
    test_c
}

ci_railguard() {
    cd "$ROOT"
    : "${RAILGUARD_SYSTEM:?RAILGUARD_SYSTEM is required}"
    run docker build -t test -f ".docker/railguards/${RAILGUARD_SYSTEM}.Dockerfile" .
    run docker run --rm test ldd /usr/local/sbin/openvas
    run sh -c 'docker run --rm test ldd /usr/local/sbin/openvas | grep libopenvas_wmiclient'
    run docker run --rm test /usr/local/bin/openvasd -h
    run docker run --rm test /usr/local/bin/scannerctl -h
    docker rmi test || true
}

ci_smokey() {
    cd "$ROOT"
    : "${OPENVAS_IMAGE:?OPENVAS_IMAGE is required}"
    (cd compose && OPENVAS_IMAGE="$OPENVAS_IMAGE" make test-environment-running)
    for attempt in 1 2; do
        (cd compose/tests/smoketest && make > /dev/null 2>&1) && return 0
        echo "smokey failed on attempt $attempt, retrying..."
    done
    (cd compose/tests/smoketest && make)
}

ci_feed_syntax() {
    version_command openvas --version
    version_command scannerctl version
    run sh -c 'scannerctl syntax --quiet "$(openvas -s | grep plugins_folder | sed '\''s/plugins_folder = //'\'')/"'
}

ci_nasl_tests() {
    cd "$ROOT"
    mkdir -p /etc/openvas
    run sh -c 'cd nasl/tests && make check'
}

ci_nasl_lint() {
    cd "$ROOT/smoketest_lint"
    run make build
    run ./run -e openvas-nasl-lint
}

local_all() {
    fmt_rust
    fmt_c
    typos_check
    license_headers
    lychee_check
    lint_rust
    test_rust
    test_c
}

VERBOSE=0
while (($# > 0)); do
    case "$1" in
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            break
            ;;
    esac
done

target="${1:-}"

case "$target" in
    fmt)
        fmt_rust
        fmt_c
        ;;
    fmt-rust)
        fmt_rust
        ;;
    fmt-c)
        fmt_c
        ;;
    lint-rust)
        lint_rust
        ;;
    lint-c)
        lint_c
        ;;
    typos)
        typos_check
        ;;
    lychee)
        lychee_check
        ;;
    license-headers)
        license_headers
        ;;
    lint)
        lint_all
        ;;
    audit-rust)
        audit_rust
        ;;
    ci-build-c)
        ci_build_c
        ;;
    ci-codeql-build-c)
        ci_codeql_build_c
        ;;
    ci-railguard)
        ci_railguard
        ;;
    ci-smokey)
        ci_smokey
        ;;
    ci-feed-syntax)
        ci_feed_syntax
        ;;
    ci-nasl-tests)
        ci_nasl_tests
        ;;
    ci-nasl-lint)
        ci_nasl_lint
        ;;
    test-rust)
        test_rust
        ;;
    test-c)
        test_c
        ;;
    test)
        test_all
        ;;
    local)
        local_all
        ;;
    -h|--help|help)
        usage
        ;;
    "")
        usage
        exit 2
        ;;
    *)
        printf 'Unknown target: %s\n\n' "$target" >&2
        usage >&2
        exit 2
        ;;
esac

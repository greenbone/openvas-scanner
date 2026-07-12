# Contributing to OpenVAS Scanner

Thank you for your interest in contributing to OpenVAS Scanner!

## Development Setup

### Using the Devcontainer (Recommended)

The easiest way to get a development environment is to use the devcontainer:

```shell
# With VS Code + Dev Containers extension:
# Open the project and click "Reopen in Container"

# Without VS Code:
cd .devcontainer
make build
make start
make enter
```

### Manual Setup

**Prerequisites:**
- C compiler (gcc/clang)
- CMake >= 3.10
- Rust 1.96.0+ (see `rust/rust-toolchain.toml`)
- Dependencies listed in [INSTALL.md](INSTALL.md)

**Build the C scanner:**
```shell
cmake -Bbuild -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

**Build the Rust components:**
```shell
cd rust
cargo build
```

## Code Style

### C Code
- Follow the existing style (GNU brace style, 80-column limit)
- Format with `clang-format`: `./check.sh fmt-c`
- All code must compile with `-Wall -Wextra -Werror -Wpedantic`

### Rust Code
- Use `rustfmt` for formatting: `cargo fmt`
- No clippy warnings allowed: `cargo clippy --all-targets -- -D warnings`
- Follow Rust API guidelines

### License Headers
All source files must include an SPDX license header. Example:
```
// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception
```

## Commit Messages

This project uses [Conventional Commits](CONVENTIONAL-COMMITS.md). Prefix your
commit messages with one of:

- `Add:` - New features (triggers minor release)
- `Fix:` - Bug fixes (triggers patch release)
- `Change:` - Changes to existing functionality (triggers major release)
- `Remove:` - Removing features (triggers major release)
- `Doc:` - Documentation changes
- `Refactor:` - Code refactoring
- `Test:` - Adding or updating tests

## Running Tests

```shell
# Run all checks (formatting, linting, tests)
./check.sh local

# Run specific checks
./check.sh fmt          # Formatting checks
./check.sh lint         # All lint checks
./check.sh test         # All tests
./check.sh test-rust    # Rust tests only
./check.sh test-c       # C tests only
```

## Pull Request Process

1. Fork the repository and create a feature branch
2. Make your changes following the style guidelines above
3. Ensure all checks pass: `./check.sh local`
4. Commit with conventional commit messages
5. Open a pull request against `main`
6. Sign the [contributor license agreement](RELICENSE/) with your first PR

## Reporting Issues

- Security vulnerabilities: See [SECURITY.md](SECURITY.md)
- Bugs and feature requests: [GitHub Issues](https://github.com/greenbone/openvas-scanner/issues)
- Questions: [Greenbone Community Portal](https://community.greenbone.net/)

# Container Image Scanner Configuration

This document explains how to tune the `[container_image_scanner.image]` section in `openvasd.toml` for customer environments.

These settings control where image data is temporarily unpacked, how many images may be scanned in parallel, and how retry behavior works when a registry request fails temporarily.

## Configuration Options

Example:

```toml
[container_image_scanner.image]
extract_to = "/var/lib/openvasd/cis"
scanning_retries = 5
max_scanning = 10
batch_size = 2
retry_timeout = "1s"
```

### `extract_to`

Path where `openvasd` temporarily extracts image content during a scan.

Example:

```toml
extract_to = "/var/lib/openvasd/cis"
```

How it works:

- `openvasd` creates scan-specific directories below this path automatically.
- Extracted image data is temporary working data, not long-term storage.
- Cleanup is attempted automatically after scanning. If cleanup fails, files may remain on disk and can be removed during maintenance.

Customer guidance:

- Use a dedicated local directory.
- Prefer fast local SSD or NVMe storage.
- Ensure the service account can create and delete directories below this path.
- Size the filesystem for concurrent scans, especially when `max_scanning` is increased.
- Avoid slow network storage unless you have verified that the performance is sufficient.

### `scanning_retries`

Number of retry attempts after a retryable image download failure.

Example:

```toml
scanning_retries = 5
```

How it works:

- Retries are only used for retryable registry-related failures.
- Typical retryable cases are temporary registry errors, temporary authentication failures, or transient blob download problems.
- Non-retryable problems, such as invalid image references, are not fixed by increasing this value.

Customer guidance:

- Use `3` to `5` in stable environments.
- Use `8` to `10` only if temporary registry or network problems are common.
- Higher values increase the time before a final failure is reported.

### `max_scanning`

Maximum number of images that may be scanned concurrently.

Example:

```toml
max_scanning = 10
```

How it works:

- This is the main throughput control for image scanning.
- Higher values can improve throughput if the system has enough network bandwidth, CPU, memory, and fast local storage.
- Higher values also increase temporary disk usage below `extract_to`.
- A value of `0` means unlimited concurrency.

Customer guidance:

- Start with a conservative value and increase gradually.
- Monitor CPU, memory, disk I/O, temporary storage usage, and registry response times while tuning.
- Avoid `0` in production because it can create uncontrolled load.

### `batch_size`

Number of images that may be picked up in one scheduler cycle.

Example:

```toml
batch_size = 2
```

How it works:

- This limits how many pending images are moved into active scanning in one cycle.
- It also controls how often the scheduler checks for more work.
- `batch_size = 2` means the scheduler checks every `2` seconds.
- Smaller values make scheduling more responsive.
- Larger values admit work in larger bursts.
- A value of `0` means unlimited batch size. In that case the scheduler still checks every `1` second.

Customer guidance:

- Keep this value small in most environments.
- `2` is a good default for many production systems.
- Avoid `0` in production unless you have validated the behavior under peak load.

### `retry_timeout`

Pause between retry attempts.

Example:

```toml
retry_timeout = "1s"
```

How it works:

- This defines how long `openvasd` waits before the next retry attempt.
- Short values retry faster but can add pressure to an unstable or rate-limited registry.
- Longer values reduce retry pressure but increase the time to complete or fail a scan.

Customer guidance:

- Start with `1s` to `5s`.
- Increase the value if your registry is overloaded or rate-limited.

## How `max_scanning` and `batch_size` Work Together

`max_scanning` controls total concurrency. `batch_size` controls how many new images may start in each scheduler cycle and also defines the scheduler interval in seconds.

Practical example:

- `max_scanning = 10`
- `batch_size = 2`

This means:

- `openvasd` checks every `2` seconds whether more images can be scanned.
- Up to `2` additional images may start in each cycle.
- The total number of actively scanned images never exceeds `10`.

This combination gives predictable ramp-up behavior and avoids sudden bursts of activity.

## Recommended Starting Points

The implementation contains these starting points for environments with a median image size of about `100 MB`:

- `1000mb/s`: `max_scanning = 10`, `batch_size = 2`
- `2500mb/s`: `max_scanning = 25`, `batch_size = 2`
- `5000mb/s`: `max_scanning = 50`, `batch_size = 2`
- `10000mb/s`: `max_scanning = 100`, `batch_size = 2`

Use these values as a starting point, not as a guarantee.

Reduce these values if:

- your images are significantly larger than `100 MB`
- the scanner host uses slow local storage
- the scanner host has limited CPU or memory
- your registry enforces strict rate limits
- the scanner host shares resources with other critical workloads

Increase these values carefully only if:

- image sizes are smaller than average
- local storage is fast and has enough free space
- the registry is able to handle the higher request volume
- monitoring shows low resource utilization during scans

## Example Profiles

### Conservative Profile

Use this profile for small environments, limited storage performance, or initial rollout.

```toml
[container_image_scanner.image]
extract_to = "/var/lib/openvasd/cis"
scanning_retries = 3
max_scanning = 5
batch_size = 2
retry_timeout = "2s"
```

### Balanced Production Profile

Use this profile as a starting point for typical production environments.

```toml
[container_image_scanner.image]
extract_to = "/var/lib/openvasd/cis"
scanning_retries = 5
max_scanning = 10
batch_size = 2
retry_timeout = "1s"
```

### High-Throughput Profile

Use this only after validating system capacity and registry behavior.

```toml
[container_image_scanner.image]
extract_to = "/var/lib/openvasd/cis"
scanning_retries = 5
max_scanning = 25
batch_size = 2
retry_timeout = "1s"
```

## Operational Recommendations

- Set `extract_to` explicitly instead of relying on a default path.
- Keep temporary extraction data on fast local storage.
- Monitor free disk space under the extraction filesystem.
- Increase `max_scanning` gradually and measure the effect.
- Tune `retry_timeout` and `scanning_retries` together.
- Avoid `max_scanning = 0` and `batch_size = 0` in customer production environments.

## Edge Cases

- `max_scanning = 0` means unlimited concurrent image scans.
- `batch_size = 0` means unlimited images may be admitted in one scheduler cycle.
- When `batch_size = 0`, the scheduler still checks for work every `1` second.
- Retries only apply to retryable registry-related failures, not to every possible scan failure.

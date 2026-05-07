# Scan Progress Calculation

The scan progress is calculated based on the number of launched plugins over the total number
of plugins per host. This is the simplest case when a scan has a single host target. Other
factors change the equation: multiple hosts, excluded hosts, and dead hosts.

The required information is always provided by `openvasd` via the route `GET /scans/{scan-id}/status`.

## Host Info Fields

The status response contains a `host_info` object:

```json
{
  "start_time": 1709111465,
  "end_time": 1709111496,
  "status": "running",
  "host_info": {
    "all": 12,
    "excluded": 3,
    "dead": 2,
    "alive": 1,
    "queued": 0,
    "finished": 1,
    "scanning": {
      "127.0.0.1": 12,
      "127.0.0.3": 75
    }
  }
}
```

The fields have the following meaning:

- **`all`**: Total number of hosts to be scanned after clean-up (duplicates, unresolvable, and
  disallowed hosts removed). Sent once at the beginning of the scan.
- **`excluded`**: Number of hosts excluded from scanning as reported by `openvasd`. This may
  differ from what the client submitted, because `openvasd` can detect duplicate or disallowed
  hosts. Always use the value provided by `openvasd`, not the client-submitted one.
- **`dead`**: Number of hosts found to be dead. With `Boreas`, this is known at scan start, but
  can increase as hosts that were initially alive may die during the scan. The client must
  update this count each time a new dead host is reported.
- **`alive`**: Number of hosts that have been fully scanned and successfully finished.
- **`queued`**: Number of hosts waiting to be scanned.
- **`finished`**: Same as `alive` for the OpenVAS scanner: both reflect hosts that completed
  scanning. Clients should use `alive` for the progress formula.
- **`scanning`**: Map of host address to scan progress (0–100). Once a host reaches 100 % it is
  removed from this map and `alive` is incremented. A value of `-1` means the host was found
  dead during scanning and `dead` is incremented instead.

## Progress Formula

```
scan_progress = (sum(scanning.values) + 100 * alive) / (all - dead)
```

## Special Case: Resuming a Scan

When resuming a stopped scan, already-finished hosts must not be scanned again. They are
therefore passed as `excluded_hosts` when creating the new scan. See [resume scan](faq/resume-scan.md)
for details on how to set that up.

Because those hosts are now excluded, the new scan starts with `all` reduced by the number of
previously finished hosts and its progress would incorrectly begin at 0 %. To compensate, the
client must track `previously_finished` and factor them into the formula.

### Example

The original scan had 15 hosts, 3 excluded, and 1 host had fully finished before the scan was
stopped. When resuming, that finished host is added to `excluded_hosts`. At the start of the
resumed scan `openvasd` reports:

```json
{
  "host_info": {
    "all": 11,
    "excluded": 4,
    "dead": 2,
    "alive": 0,
    "queued": 9,
    "finished": 0,
    "scanning": {}
  }
}
```

The client knows `previously_finished = 1`. The adjusted formula is:

```
scan_progress = (sum(scanning.values) + 100 * (alive + previously_finished))
              / (all + previously_finished - dead)
```

So at the very start of the resumed scan:

```
scan_progress = (0 + 100 * (0 + 1)) / (11 + 1 - 2) = 10 %
```

The resumed scan therefore starts at 10 % rather than 0 %, correctly reflecting the work
already done.

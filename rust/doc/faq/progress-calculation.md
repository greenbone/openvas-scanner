# How do I calculate a scan progress?

The required information for the progress calculation will be always provided by `openvasd`, via the route `scan/{scan-id}/status`.
You get a json object which looks like as following:
```
{
  "start_time": 1709111465,
  "end_time": 1709111496,
  "status": "succeeded",
  "host_info": {
    "all": 12,
    "excluded": 3,
    "dead": 2,
    "alive": 1,
    "queued": 0,
    "finished": 1,
    "scanning": [
      "127.0.0.1": 12,
      "127.0.0.3": 75,
    ]
  }
}
``` 

Then, with this information you can calculate the scan progress with the following suggested formula:

```
scan_progress = (sum_of_scanning_hosts_values + 100 * finished)
          / (all - dead)
```
For the example given above, the progress is:

```
scan_progress = (12 + 75 + 100 * 1) / (12 - 2) = 18.7 %
```

## Special case for resume task

When you resume a task, the finished hosts should not be scanned again. Therefore they are sent in the list of excluded hosts. Please read the documentation for [resume scan](resume-scan.md).
In this case, a resume scan with some finished hosts, should not start with a progress with 0%, but a progress according with the already finished hosts.

Then, imagine that the scan of example above, with an initial target of 15 hosts, was stopped/interrupted and you want to resume it. It has an already finished hosts. This hosts is added to the list of `excluded hosts`.
At the beginning of the resumed scan you have:

```
{
  "start_time": 1709111465,
  "end_time": 1709111496,
  "status": "succeeded",
  "host_info": {
    "all": 11,
    "excluded": 4,
    "dead": 2,
    "alive": 1,
    "queued": 0,
    "finished": 1,
    "scanning": [
    ]
  }
}

``` 

As you already know the amount of previously finished hosts, you use this value for the progress calculation as well. You have to add the previously finished hosts to the total amount of hosts and add them to the `finished` host as well, because in the end, they were already scanned and finished.
The suggested formula for calculating the scan progress of a resume task:
```
scan_progress = (sum_of_scanning_hosts_values + 100 * (finished + previously_finished))
          / (all + previously_finished - dead)

```
Then, the scan progress for a resume task will start from:

```
scan_progress = (0 + 100 * (0 + 1) / (11 + 1 - 2) = 10 %
```

# How do I calculate a scan progress?

The scan progress is calculated in base of the amount of launched plugins over the total amount of plugins per host. This would be easiest case, when a scan has a single host target.

Other cases change the equation, like having many hosts, excluded hosts and dead hosts.

The required information for the calculation will be always provided by `openvasd`, but is a client task to keep track of the numbers.

### Excluded hosts

`openvasd` provides the amount of excluded hosts, which can differ from the amount sent by the client. This happens because openvasd can find a duplicate host in the list, or a host which is not system allowed. 

Then, the amount of excluded hosts to be used for the progress calculation, is the one provided by `openvasd`.

### Total hosts

Is the amount of hosts to be scanned after a clean up. This means, after removing duplicated, excluded, unresolveble and not allowed hosts. I sent once at the beginning of the scan.

### Dead hosts

With `Boreas` it is possible to know at the beginning of the scan, how many alive hosts are in the target and how many are dead. However, this number can change if later a host which is found alive at the scan start, dies during the the scan. 

So, the client receives a message at the beginning with the number of dead hosts, but this number must be updated each time a new dead hosts is found during the scan.

### Alive hosts

Is the amount of hosts which were already scanned and successfully finished.

### Current scan hosts

`openvasd` sends to the client a list of the current scanned hosts and its progress. The host progress, as explained above, is the the amount of launched plugins over the total amount of plugins.

Once the host progress reaches the 100%, the host is removed from the list and adds +1 to the `alive hosts` counter. 

The same happens with a dead hosts when it is found as dead during the scan. The dead hosts is removed from this list and adds +1 to the `dead hosts` counter.

## Example:

Suppose a target with 15 hosts and 3 from the list are excluded. `openvas` found a total of 12 hosts. Also, during the alive test scan with `Boreas`, or even during the scan, 2 hosts where found dead.
One hosts is already scanned, and 2 hosts are currently being scanned.

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

Then, with this information you can calculate the scan progress with the following formula:

```
scan_progress = (sum_of_host_scanning_values + 100 * alive)
          / (all - dead)
```
For this example, the progress is:

```
scan_progress = (12 + 75 + 100 * 1) / (12 - 2) = 18.7 %
```

## Special case for resume task

When a resume task, the finished hosts should not be scanned again. Therefore they are sent in the list of excluded hosts. Please read the documentation for [resume scan](resume-scan.md).
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

As you already know the amount of finished hosts, you use this value for the progress calculation. You have to add the finished hosts to the total amount of hosts and the add them also to the `count_alive`, because in the end, they were already scanned and finished.
The suggested formula for calculating the scan progress of a resume task:
```
scan_progress = (sum_of_host_status_values + 100 * (count_alive + finished))
          / (total_hosts + finished - count_dead)

```
Then, the scan progress for a resume task will start from:

```
scan_progress = (0 + 100 * (0 + 1) / (11 + 1 - 2) = 10 %
```


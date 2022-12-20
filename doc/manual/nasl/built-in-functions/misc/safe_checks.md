# safe_checks

## NAME

**safe_checks** - takes no argument and returns the boolean value of the “safe checks” option.

## SYNOPSIS

*bool* **safe_checks**();

**safe_checks** - takes no argument and returns the boolean value of the “safe checks” option.

## DESCRIPTION

Dangerous plugins which may crash the remote service are expected to change their behavior when “safe checks” is on.

Usually, they just identify the service version (e.g. from the banner) and check if it is known as vulnerable.

In `safe checks mode` plugins from the most dangerous categories (`ACT_DESTRUCTIVE_ATTACK`, `ACK_DENIAL` and `ACT_KILL_HOST`) are not launched. 
Meaning you do not need to test the value of `safe_checks` in those scripts.


## EXAMPLES

```cpp
if (safe_checks())
  exit(0);
```

## SEE ALSO

**[defined_func(3)](defined_func.md)**,
**[dump_ctxt(3)](dump_ctxt.md)**,
**[gettimeofday(3)](gettimeofday.md)**,
**[isnull(3)](isnull.md)**,
**[localtime(3)](localtime.md)**,
**[make_array(3)](make_array.md)**,
**[make_list(3)](make_list.md)**,
**[v(3)](v.md)**,
**[max_index(3)](max_index.md)**,
**[mktime(3)](mktime.md)**,
**[safe_checks(3)](safe_checks.md)**,
**[sleep(3)](sleep.md)**,
**[typeof(3)](typeof.md)**,
**[usleep(3)](usleep.md)**,
**[unixtime(3)](unixtime.md)**,
**[get_byte_order(3)](get_byte_order.md)**,
**[gzip(3)](gzip.md)**,
**[gunzip(3)](gunzip.md)**,
**[dec(3)](dec.md)**,
**[keys(3)](keys.md)**,
**[sort(3)](sort.md)**,
**[exit(3)](exit.md)**,
**[rand(3)](rand.md)**,
**[open_sock_kdc(3)](open_sock_kdc.md)**,

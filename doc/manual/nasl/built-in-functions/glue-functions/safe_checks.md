# safe_checks

## NAME

**safe_checks** - takes no argument and returns the boolean value of the “safe checks” option.

## SYNOPSIS

*bool* **safe_checks**();

**safe_checks** takes no argument and returns the boolean value of the “safe checks” option.

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

**[exit(3)](exit.md)**,

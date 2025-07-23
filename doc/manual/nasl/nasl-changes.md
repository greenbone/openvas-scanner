# Breaking changes in next version
A list of breaking changes we might want to do in a future NASL version.

## Autoconversion
* Simplify the autoconversion rules (i.e. strings magically being turned into integers, arrays into bools and so on, ...). Prefer throwing errors over implicit conversions.

## Obsolete operators
Get rid of barely used operators such as the `x` operator and `>>>=`.

## Control flow
Disallow using `break` to escape from functions/the script.

## Forking
Remove the forking concept altogether.

## FCT_ANON_ARGS
Think of a cleaner construct to allow variadics.

# end_denial

## NAME

**end_denial** - end denial

## SYNOPSIS

*bool* **end_denial**();

**end_denial** takes no arguments.

## DESCRIPTION

After calling start_denial before your test, it returns TRUE if the target host is still alive and FALSE if it is dead. **[start_denial(3)](start_denial.md)** must be called before.

## RETURN VALUE

Returns TRUE if the target host is still alive and FALSE if it is dead. 

## SEE ALSO

**[start_denial(3)](start_denial.md)**

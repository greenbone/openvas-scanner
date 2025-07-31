# NASL Grammar

## Preliminary remarks

- Comments start with a # and finish at the end of the current line.
  
## Statements
A NASL program is a list of statements. Statements are delimited by semicolons, although semi-colons may be omitted after block-statements (such as loops, ifs, function declarations, ...).
A statement is any of the following:
- Function declaration: **function** identifier ( arguments ) { block }
- An expression statement: expr
- if block: **if** ( expr ) { block } **else if** (expr ) { block } **else** { block }
- for loop: **for** ( func; expr; func; ) { block }
- while loop: **while** ( expr ) { block }
- repeat loop: **repeat** instr **until** expr
- foreach loop: **foreach** identifier ( array ) { block }
- include statement: **include**( "file.inc" )
- local variable: **local_var** variable
- global variable: **global_var** variable
- control flow via **break** / **continue** / **return** ( expr )

## Expressions
An expression can be one of the following:
- Atom: A base expression such as a literal, identifier, or function call.
- Binary: A binary operation (e.g., `a + b`).
- Unary: A unary operation (e.g., `-a` or `!b`).
- Assignment: An assignment expression (e.g., `x = y`)
- Increments: Similarly, increments are also allowed (e.g. `++x` or `y++`)

### Atoms
An Atom is a fundamental expression type with no further decomposition (other than subexpressions). It includes:

- Literals: Primitive values (e.g., integer, string, etc.).
- Variables: A variable name.
- Arrays: An array literal (e.g. `[1, 2, 3]`)
- Array access: An expression accessing an array element (e.g. `arr[0]`)
- Function calls: A function call (for example `f(x, y)`)

**Literals**
A literal may be any of
- Boolean: `FALSE` or `TRUE`.
- Integer: `100`, `0b010101` (binary, leading `0b`), `01234567` (octal, leading 0), `0xff` (hex, leading `0x`).
- Strings: Enclosed in `"`, for example `"foo"`.
- Byte arrays: Similar to strings, but enclosed in `'`, i.e. `'foo'`.
- Arrays: For example `[1, 2, 3]`.
- Null: `NULL`.
- IP addresses: For example `127.0.0.1`.

**Function calls**
Function calls are written as **fn_name** (args), where args is a comma separated list of named arguments given as `arg1: val1, arg2: val2, arg3: val3, ...`. In special cases (for some builtin functions) unnamed arguments are also accepted, i.e. **fn_name** (val1, val2, val3, ...).
**x operator**
This deprecated syntax allows repeating the previous function calls `n` times, i.e. `fn_name(args) x 100` will repeat `fn_name` 100 times.

**Array access**
Indexing into arrays/array-likes (such as strings) is done by `[index]`, e.g. `foo[5]`.

### Unary expressions
A unary expression is any expression preceded by a unary operator, such as `!x` or `-y`. Available unary operators are
`-`: Integer negation.
`+`: For integers, leaves the value modified.
`!`: Boolean not.
`~`: Bitwise not.

### Binary exprs
A binary expression is two expressions along with a binary operator, such as `x + y` or `a && b`.
Available binary operators are:

Arithmetic:
- `+` is the addition operator.
- `-` is the subtraction operator.
- `*` is the multiplication operator.
- `/` is the integer division operator.
- `%` is the integer modulo (remainder) operator.
- `**` is the power operator.
- `>>` and `<<` are bitshift operators. `>>>` is equivalent to `>>`, but performs the operation after casting the operands to unsigned integers.
- `&` and `|` are bitwise and/or.
- `^` is bitwise xor.

Logical:
- `&&` and `||` are boolean and/or. The operators short-circuit (i.e. the `foo=3` in `FALSE && (foo = 3)` will not be executed).
- `==` is the equals operator.
- `!=` is the not-equals operator.
- `>`, `<`, `>=` and `<=` are greater/less and greater equal / less equal respectively.

Strings
- `><` is the string-match operator. It checks if the LHS contains the RHS as a substring.
- `>!<` is the negated string-match operator.
- `=~` is the regex matching operator. It interprets the RHS as a regular expression and checks whether the LHS matches the regular expression.
- `!~` is the negated regex matching operator.
Note: `=~` and `!~` support the (standard extended POSIX) regex pattern. See [Regular Expression Functions](../built-in-functions/regular-expressions/index.md) for more background info on the supported regex expression support.

### Assignment
An assignment expression is syntactically similar to a binary expression but assigns the RHS expression to the LHS value. The LHS is restricted to valid assignment targets:
```nasl
a = 3; // assigns 3 to a
a[1] = 3; // assigns 3 to the second element of a (an array).
"foo" = 3; // ERROR: string literal is not a valid assignment target.
```

Available assignment operators:
`=`: Simple assignment.
`+=`: Adds the RHS to the LHS.
`-=`: Subtracts the RHS from the LHS.
`*=`: Multiplies the LHS by the RHS.
`/=`: Divides the LHS by the RHS.
`%=`: Computes (LHS % RHS) and assigns it to LHS.
`<<=`: Computes `(LHS << RHS)` and assigns it to LHS.
`>>=`: Computes `(LHS >> RHS)` and assigns it to LHS.
`>>>=`: Computes `(LHS >>> RHS)` and assigns it to LHS.

### Increment
An increment expression is syntactically similar to a unary expression and is restricted to valid assignment targets as well:
```nasl
a++; // Increments foo by 1
a[1]++; // Increments the second element of a (an array) by 1.
"foo"++; // ERROR: string literal is not a valid assignment target.
```

Available increment operators:
`++`: Increments operand by one.
`--`: Decrements operand by one.

Postfix operators (`x++` and `x--`) evaluate to the value of x, then modify the value. For example, in `x = 10; x++;`, the second statement evaluates to `10`.
Prefix operators (`++x` and `--x`) modify the value, then evaluate to the new value. For example, in `x = 10; ++x;`, the second statement evaluates to `11`.

## Operator precedence
| Operators                       | Associativity |
| ------------------------------- | ------------- |
| ++ --                           | None          |
| **                              | Right         |
| ~- (unary minus)                | Left          |
| = += -= *= /= %= <<= >>= >>>=   | Right         |
| !                               | Left          |
| * / %                           | Left          |
| + -                             | Left          |
| << >> >>>                       | Left          |
| &                               | Left          |
| ^                               | Left          |
| \|                              | Left          |
| < <= > >= == != <> =~ !~ >!< >< | None          |
| &&                              | Left          |
| \|\|                            | Left          |

Note, in particular, that assignment has relatively high precedence, allowing expressions like
```nasl
if (!x = foo() ) { ... }
```
which will first assign the result of the `foo()` call to `x`, and then negate the value.

## Loops and Control Flow
### If
If statements are written as
`if (condition) block` where `block` is either a single statement (in which case enclosing braces may be omitted) or multiple statements (in which case the braces are necessary).

### Loops
The following loops exist:
- While loop: `while(cond) block;` executes the block as long as the condition is TRUE.
  If the condition is FALSE, the block is never executed.
- For loop: `for (expr1; cond; expr2) block;` is similar to the C operator and is equivalent to `expr1; while(cond) block; expr2;`
- `foreach var (array) block;` iterates over all elements in an array or array-like.
- `repeat block; until (cond);` executes the blocks as long as the condition is TRUE. The block is executed at least once.
- `break` breaks the current loop and jumps at its exit.
  If you are not inside a loop, the behavior is undefined.
- `continue` jumps to the next step of the loop.
  If you are not inside a loop, the behavior is undefined.
- `return` returns a value from the current function.

## Variable Declarations
Variables are declared implicitly upon assignment. For example, `a = 1;` will declare the variable a even if it did not exist before.

NASL uses global and local variables. Local variables are created in a function and stop existing as soon as the function returns. Global variables exist for the entire script.

In some cases, you might want to make the scope of a new variable explicit:
1. If you want to write into a global variable from within a function.
2. If you want to be sure that you are declaring a new local variable and not overwriting a global variable with the same name.

In these cases, a variable can explicitly be declared as follows:
- `local_var var;`
- `global_var var;`

### Function Declarations

Functions are declared via
```nasl
function fn_name (arg1, arg2, arg3, ...) {
}
```

Any arguments in user-defined functions are named arguments, that is, they need to be explicitly named at the call site:
`fn_name (arg1: 1, arg2: "foo", arg3: FALSE)`


# Types
NASL handles the following data types:
- **Boolean**
- **Integer**
- **Strings**
- **Data** (strings represented as raw bytes)
- **Arrays**
- **Null**

# Current behavior
## Type autoconversion
**Booleans**
Every type is automatically converted into booleans when a boolean is needed (for example in `if (x) { ... }`)
- The undefined or null value is false
- All integers except 0 are true
- Strings are true if not empty and not "0".
- Arrays are always true whether they are empty or not

**NULL**
  NULL and the array operator Reading an array element from a NULL value will immediately convert it into an array. An empty array of course, but no more an undefined variable.. For example:
  ```
  v = NULL;
  # isnull(v)=TRUE and typeof(v)="undef"
  x = v[2];
  # isnull(x)=TRUE and typeof(x)="undef"
  # But isnull(v)=FALSE and typeof(v)="array"
  ```

  NULL and isnull If it should be checked whether a variable is undefined, isnull(var) has to be used. Testing the equality with the NULL constant (var == NULL) is not a good idea as NULL will be converted to 0 or the empty string "" according to the type of the variable. This is necessary to ensure that variables are "automatically initialized" – changing this would probably break some existing scripts.
  
**String**
For binary operators:
- If one of the arguments is NULL, + returns the other one.
- If one of the arguments is a string, the other argument is converted to a string.
- If one of the arguments is an integer, the other is converted to an integer.
- In any other case, NULL is returned.

### Special Behavior
- break can (but should not) be used to exit from a function or the script.OB
- The “magical strings” from NASL1 have been removed. In NASL1, adding a string to an integer might give an integer if the string contained only digits.
- The minus operator follows the same type conversion rules as plus.
- Using unitialized variables is bad. However, to ensure that old scripts still work, the NULL undefined value will be converted to 0 or “” according to the context (integer or string). That is why isnull has to be used to test if a variable is undefined. See “Warnings about the NULL value” in NASL Documentation.

### Retrieving Function Arguments
The `_FCT_ANON_ARGS` variable exists in order to allow access to anonymous function args from within a function.
This variable will be NULL in interpreters below NASL_LEVEL 2190.

The following may be put at the start of scripts that need this function:

```
if (NASL_LEVEL < 2190) exit(0); # _FCT_ANON_ARGS is not implemented
```

1. Writing to _FCT_ANON_ARGS is undefined. Currently, the memory is wasted but the value cannot be read back.
2. Using _FCT_ANON_ARGS to try to read named arguments is bad too. Currently, there is a protection and a NULL value is returned.

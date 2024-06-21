# NASL Grammar

## Preliminary remarks

- A comment starts with a # and finishes at the end of the current line. It is ignored by the lexical analyzer.
- “Blanks” may be inserted anywhere between two lexical tokens. 
A blank may be a sequence of white space, horizontal or vertical tabulation, line feed, form feed or carriage return characters; or a comment.
- Token are parsed by a lexical analyzer and returned to the parser.
  - As the lexical analyzer returns the longer token it finds, expressions like `a+++++b` without any white space are erroneous because they will be interpreted as `a++ ++ + b`, i.e., `(a++ ++) + b` just like in ANSI C .
  - You have to insert spaces: `a++ + ++b`
  - You cannot insert spaces in the middle of multiple character tokens, e.g., `x = a + +;` will not parse. Write `x = a ++;`
  
## Syntax

- a code block / an expression ends with a semi-colon: expr;
- function declaration: **function** identifier ( arguments ) { block }
- function call: **identifier** ( arguments )
- if block: **if** ( expr ) { block } **else if** (expr ) { block } **else** { block }
- for loop: **for** ( func; expr; func; ) { block }
- while loop: **while** ( expr ) { block }
- repeat loop: **repeat** instr **until** expr
- foreach loop: **foreach** identifier ( array ) { block }
- include inc file: **include**( "file.inc" )
- define variable: **var** = string, int, ...
- local variable: **local_var** variable
- global variable: **global_var** variable

## Types

NASL handles the following data types:

- **Integers** Any sequence of digits with an optional minus sign is an integer. NASL uses the C syntax: octal numbers can be enter by starting with 0 and hexadecimal with 0x (i.e., 0x10 = 020 = 16).

- **Strings**
  - Can be declared with single or double quotes: "string", 'string'
  - "Impure" strings
    - Entered between double quotes
    - Not converted (backslashes remain backslashes)
    - Transformed into "pure" strings by internal string function
  - "Pure" strings
    - Returned by string function or entered between simple quotes
- **Arrays**
Can be indexed with integers or strings
- **NULL** value
  Result if an initialized value is read or return of internal function in case of severe an error
  **Warnings about the NULL value**
  NULL and the array operator Reading an array element from a NULL value will immediately convert it into an array. An empty array of course, but no more an undefined variable. Changing this means big modifications in the NASL interpreter. For example:
  ```
  v = NULL;
  # isnull(v)=TRUE and typeof(v)="undef"
  x = v[2];
  # isnull(x)=TRUE and typeof(x)="undef"
  # But isnull(v)=FALSE and typeof(v)="array"
  ```

  NULL and isnull If it should be checked whether a variable is undefined, isnull(var) has to be used. Testing the equality with the NULL constant (var == NULL) is not a good idea as NULL will be converted to 0 or the empty string "" according to the type of the variable. This is necessary to ensure that variables are "automatically initialized" – changing this would probably break some existing scripts.
- **Booleans**
  Not a standalone type, comparison operators return 0 for FALSE and 1 for TRUE
  Any other value is converted:
  - The undefined or null value is FALSE
  - Integers are TRUE if not null, 0 is FALSE
  - Strings are TRUE if not empty an not "0"
  - Arrays are always TRUE whether they are empty or not


## Operators
### General Operators

- = is the assignment operator.

  - `x=42`; puts 42 into the variable x. The previous value is forgotten.

  - `x=y`; copies the value of variable y into x. If y was undefined, x becomes undefined too.

- `[ ]` is the array index operator.

  - A variable cannot be atomic and an array at the same time. If the type is changed, the previous value(s) is/are lost.
  - However, this operator can be used to extract a character from a string: if `s = "abcde"`, then `s[2] = "c"`.
  In NASL1, this could be used to change the character too: one could write `s[2] = "C";` and s became `"abCde"`. This is no longer true; the insstr function has to be used and something like `s = insstr(s, "C", 2, 2);` has to be written.
  - y[1] = 42; makes an array out of y and puts 42 in the second element. If y was not an array, it’s first undefined.

### Arithmetics Operators

Note: There is no strict rule on the integer size in NASL. The interpreter implements them with the native "int" C type, which is 32 bit long on most systems, and maybe 64 bit long on some . There is no overflow or underflow protection.

- `+` is the addition operator.
- `-` is the subtraction operator.
- `*` is the multiplication operator.
- `/` is the integer division operator.
  Note:
   - NASL does not support floating point operations.
   - Division by zero will return 0 instead of crashing the interpreter.
- `%` is the modulo. Once again, if the second operand is null, the interpreter will return 0 instead of crashing on SIGFPE.
- `**` is the exponentiation or power function.

### C Operators

NASL imported some operators from C:

- `++` is the pre-incrementation (`++x`) or post-incrementation (`x++`).
- `++x` adds 1 to x and returns the result; `x++` adds 1 to x but returns the previous value.
- `-` is the pre-decrementation (`–x`) or post-decrementation (`x–`).
- `+= -= *= /= %=` have the same meaning as in C, e.g., `x += y;` is equivalent to `x = x + y;` but x is evaluated only once. This is important in expressions like `a[i++] *= 2;` where the index “i” is incremented only once.
- `<<=` and `>>=` also exist; we added `>>>=`

### String Operators

- `+` is the string concatenation. However, you should better use the string function.
- `-` is the “string subtraction”. It removes the first instance of a string inside another.
  For example `’abcd’ - ’bc’` will give `’ad’`.
- `[]` extracts one character from the string, as explained before.
- `><` is the “string match” operator. It looks for substrings inside a string.
  `’ab’ >< ’xabcdz’` is TRUE; `’ab’ >< ’xxx’` is FALSE.
- `>!<` is the “string don’t match” operator. It looks for substrings inside a string and returns the opposite as the previous operator.
  `’ab’ >!< ’xabcdz’` is FALSE; `’ab’ >!< ’xxx’` is TRUE.
- `=~` is the “regex match” operator. It is similar to a call to the internal function ereg but is quicker because the regular expression is compiled only once when the script is parsed.
  `s =~ "[ab]*x+"` is equivalent to `ereg(string:s, pattern:"[ab]*x+", icase:1)`
- `!~` is the “regex don’t match” operator. It gives the opposite result of the previous one.

Note: =~ and !~ supports the (standard extended POSIX) regex pattern. See Supported regex expression syntax for NASL Functions for more background info on the supported regex expression support.

### Compare Operators

- `==` is TRUE if both arguments are equals, FALSE otherwise.
- `!=` is TRUE if both arguments are different, TRUE otherwise.
- `>` is the “greater than” operator.
- `>=` is the “greater than or equal” operator.
- `<` is the “lesser than” operator.
- `<=` is the “lesser than or equal” operator.

### Logical Operators

- `!` is the logical “not”. TRUE if its argument is FALSE, FALSE otherwise.
- `&&` is the logical “and”. Note that if the first argument is FALSE, the second is not evaluated.
- `||` is the logical “or”. If the first argument is TRUE, the second is not evaluated.

### Bit Fields Operators

- `~` is the arithmetic “not”, the 1-complement
- `&` is the arithmetic “and”.
- `|` is the arithmetic “or”.
- `^` is the arithmetic “xor” (exclusive or).
- `<<` is the logical bit shift to the left.
- `>>` is the arithmetic/signed shift to the right.
The sign bit, if any, is propagated.
- `>>>` is the logical/unsigned shift to the right.
  The sign bit is pushed to the right and replaced by zero.

In all shift operators, the count is on the right, i.e., `x>>2` is equivalent to `x/4` and `x<<2` is `x*4`.

### Special Behavior

- break can (but should not) be used to exit from a function or the script.OB
- In case its arguments have different types, + now tries very hard to do something smart, i.e., a string concatenation, then an integer addition. It prints a warning, though, because such automatic conversion is dangerous.
  - If one of its argument is undefined, + returns the other one.
  - If one of its argument is a “pure string”, the other argument is converted to a string if necessary, and the result is a “pure string”. An “Impure string” is converted to a pure string without escape sequence interpretation, i.e., "AB\n"+’de’ gives ’AB\\nde’, i.e., “AB”, a backslash, then “nde”.
   - If one of its argument is an “impure string”, the second argument is converted to a string if necessary and the result is an “impure string”, i.e., "ABC"+2 gives "ABC2".
   - If one of its argument is an integer, the other is converted to an integer and the result is an integer.
   - In any other case, NULL is returned.
- The “magical strings” from NASL1 have been removed. In NASL1, adding a string to an integer might give an integer if the string contained only digits.
- The minus operator follows the same type conversion rules as plus.
- Using unitialized variables is bad. However, to ensure that old scripts still work, the NULL undefined value will be converted to 0 or “” according to the context (integer or string). That is why isnull has to be used to test if a variable is undefined. See “Warnings about the NULL value” in NASL Documentation.

## Precedence
| Operators                       | Associativity |
| ------------------------------- | ------------- |
| ++ --                           | None          |
| **                              | Right         |
| ~- (unary minus)                | Left          |
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
| = += -= *= /= %= <<= >>= >>>=   | Right         |


## Loops and Control Flow

### Operators

- `for (expr1; cond; expr2) block;` is similar to the C operator and is equivalent to `expr1; while(cond) block; expr2;`
  A classical construction to count from 1 to 10 is: `for(i=1;i<=10;i++) display(i,’{\n’);`
- `foreach var (array) block;` iterates all elements in an array.
  Note that var iterates through the values stored in the array, not the indexes. If that is desired, use: foreach var (keys(array)) block;
- `while(cond) block;` executes the block as long as the condition is TRUE.
  If the condition is FALSE, the block is never executed.
- `repeat block; until (cond);` executes the blocks as long as the condition is TRUE. The block is executed at least once.
- `break` breaks the current loop and jumps at its exit.
  If you are not inside a loop, the behavior is undefined.
- `continue` jumps to the next step of the loop.
  If you are not inside a loop, the behavior is undefined.
- `return` returns a value from the current function.

## Declarations

###Variable Declarations

NASL uses global and local variables. Local variables are created in a function and stop existing as soon as the function returns. When the interpreter looks for a variable, it first searches in the current function context, then in the calling context (if any) etc., until it reaches the top level context that contains the global variables.

Normally, a variable does not have to be declared: either it exists, because it was already used in this context, or because a calling function used it, or it will be created in the current context.
However, this may be dangerous in some cases:

1. If you want to write into a global variable from within a function and cannot be sure that the variable was created first in the top level context, or created as a local variable in a calling function context.
2. If you want to be sure that you are creating a brand new local variable and not overwriting a global variable with the same name.

A variable can explicitly be declared as follows:

- local_var var;
- global_var var;

If the variable already exists in the specified context, an error message is returned.

### Function Declarations

 - function name (argname1, argname2) block;

Note: The argument list may be empty, but if it is not, user-defined function parameters must be named. Unnamed arguments may be used without being declared.

### Retrieving Function Arguments

Inside an NASL function, named arguments are just accessed as any local variable. Unnamed arguments are implemented through the special array _FCT_ANON_ARGS.
This variable will be NULL in interpreters below NASL_LEVEL 2190.

The following may be put at the start of scripts that need this function:

```
if (NASL_LEVEL < 2190) exit(0); # _FCT_ANON_ARGS is not implemented
```

1. Writing to _FCT_ANON_ARGS is undefined. Currently, the memory is wasted but the value cannot be read back.
2. Using _FCT_ANON_ARGS to try to read named arguments is bad too. Currently, there is a protection and a NULL value is returned.

### Calling Functions

Here is an example with named arguments:
```
function fact(n)
{
   local_var i, f;
   f = 1;
   for (i = 1; i <= n; i ++) f *= i;
   return f;
}
display("3 ! = ", fact(n: 3), "\n");
```

And the same with unnamed arguments:
```
function fact()
{
   local_var i, f;
   f = 1;
   for (i = 1; i <= _FCT_ANON_ARGS[0]; i ++) f *= i;
   return f;
}
display("3 ! = ", fact(3), "\n");
```

And another, mixing the two flavors:
```
function fact(prompt)
{
   local_var i, f;
   f = 1;
   for (i = 1; i <= _FCT_ANON_ARGS[0]; i ++)
   {
      f *= i;
      display(prompt, i, ’! = ’, f, ’\n’);
   }
   return f;
}
n = fact(3, prompt: ’> ’);
```



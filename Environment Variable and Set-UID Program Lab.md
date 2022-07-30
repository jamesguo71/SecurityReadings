# Environment Variable and Set-UID Program

## Fei Guo, July 29

Lab link: https://seedsecuritylabs.org/Labs_20.04/Files/Environment_Variable_and_SetUID/Environment_Variable_and_SetUID.pdf

## Passing Environment Variables from Parent Process to Child Process

The child will inherit its parent process's env vars.

## Environment Variables and execve()

When we create a new process using execve, we need to pass the `environ` variable to execve, e.g,  

`execve("/usr/bin/env", argv, environ);`

Otherwise the new process will not inherit any environment variables from the calling process.

## Environment Variables and system()

system call will call execl to execute /bin/sh, and excel() calls execve(), passing to it the environment variables array. So the environment variables of the calling process is passed to the new program /bin/sh.

## Environment Variable and Set-UID Programs

All the environment variables set in the shell process (parent) get into the Set-UID child process.

## The PATH Environment Variable and Set-UID Programs

We can change the behavior of a Set-UID program by changing its env vars:

First,

`$ export PATH=/home/seed:$PATH`

Then make another `ls` program under the path above. Then the program will use our own `ls` instead of the system one:

```c
int main()
{
	system("ls");
	return 0;
}
```

Note some shell may have countermeasures against this.

## The LD PRELOAD Environment Variable and Set-UID Programs

Due to security concern, env vars like `LD_*` will not be passed to Set-UID processes.

## Invoking External Programs Using system() versus execve()

For a Set_UID program using system like this, 
```c
// task8.c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char *argv[]){
    char *v[3];
    char *command;
    if(argc < 2) {
        printf("Please type a file name.\n");
        return 1;
    }
    v[0] = "/bin/cat"; v[1] = argv[1]; v[2] = NULL;
    command = malloc(strlen(v[0]) + strlen(v[1]) + 2);
    sprintf(command, "%s %s", v[0], v[1]);
    // Use only one of the followings.
    system(command);
    // execve(v[0], v, NULL);
    return 0;
}
```
Set-UID to root by by:
```
gcc -o task8 task8.c
sudo chown root task8
sudo chmod 4755 task8
```

We can concatenate another command and get a shell in root priviledge:

```task8 "file; /bin/sh"```

Using execve will help prevent this problem.

## Capability Leaking

The following program leaks capability because `setuid` is called after opening the `etc/zzz` file with root privilege, so the malicious data will be appended!

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void main()
{
  int fd;
  fd = open("etc/zzz", O_RDWR | O_APPEND);
  if (fd == -1)
  {
    printf("cannot open it \n");
    exit(0);
  }
  sleep(1);
  setuid(getuid());
  if(fork())
  {
    close(fd);
    exit(0);
  }
  else
  {
    write(fd, "malicious data\n", 15);
    close(fd);
  }
  return 0;
}
```
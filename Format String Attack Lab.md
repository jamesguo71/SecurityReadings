# Format String Vulnerability Lab

## Lab Link: https://seedsecuritylabs.org/Labs_20.04/Software/Format_String/

## The Vulnerable Program

For this lab, we need to turn off ASLR.

```bash
$ sudo sysctl -w kernel.randomize_va_space=0
```

The vulnerable program `format.c`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

/* Changing this size will change the layout of the stack.
 * Instructors can change this value each year, so students
 * won't be able to use the solutions from the past.
 * Suggested value: between 10 and 400  */
#ifndef BUF_SIZE
#define BUF_SIZE 100
#endif


#if __x86_64__
  unsigned long target = 0x1122334455667788;
#else
  unsigned int  target = 0x11223344;
#endif 

char *secret = "A secret message\n";

void dummy_function(char *str);

void myprintf(char *msg)
{
#if __x86_64__
    unsigned long int *framep;
    // Save the rbp value into framep
    asm("movq %%rbp, %0" : "=r" (framep));
    printf("Frame Pointer (inside myprintf):      0x%.16lx\n", (unsigned long) framep);
    printf("The target variable's value (before): 0x%.16lx\n", target);
#else
    unsigned int *framep;
    // Save the ebp value into framep
    asm("movl %%ebp, %0" : "=r"(framep));
    printf("Frame Pointer (inside myprintf):      0x%.8x\n", (unsigned int) framep);
    printf("The target variable's value (before): 0x%.8x\n",   target);
#endif

    // This line has a format-string vulnerability
    printf(msg);

#if __x86_64__
    printf("The target variable's value (after):  0x%.16lx\n", target);
#else
    printf("The target variable's value (after):  0x%.8x\n",   target);
#endif

}


int main(int argc, char **argv)
{
    char buf[1500];


#if __x86_64__
    printf("The input buffer's address:    0x%.16lx\n", (unsigned long) buf);
    printf("The secret message's address:  0x%.16lx\n", (unsigned long) secret);
    printf("The target variable's address: 0x%.16lx\n", (unsigned long) &target);
#else
    printf("The input buffer's address:    0x%.8x\n",   (unsigned int)  buf);
    printf("The secret message's address:  0x%.8x\n",   (unsigned int)  secret);
    printf("The target variable's address: 0x%.8x\n",   (unsigned int)  &target);
#endif

    printf("Waiting for user input ......\n"); 
    int length = fread(buf, sizeof(char), 1500, stdin);
    printf("Received %d bytes.\n", length);

    dummy_function(buf);
    printf("(^_^)(^_^)  Returned properly (^_^)(^_^)\n");

    return 1;
}

// This function is used to insert a stack frame between main and myprintf.
// The size of the frame can be adjusted at the compilation time. 
// The function itself does not do anything.
void dummy_function(char *str)
{
    char dummy_buffer[BUF_SIZE];
    memset(dummy_buffer, 0, BUF_SIZE);

    myprintf(str);
}
```

This is the program running on a Server:

`server.c`
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>

#define PROGRAM "format"
#define PORT    9090

int socket_bind(int port);
int server_accept(int listen_fd, struct sockaddr_in *client);
char **generate_random_env();

void main()
{
    int listen_fd;
    struct sockaddr_in  client;

    // Generate a random number
    srand (time(NULL));
    int random_n = rand()%2000; 
   
    // handle signal from child processes
    signal(SIGCHLD, SIG_IGN);

    listen_fd = socket_bind(PORT);
    while (1){
	int socket_fd = server_accept(listen_fd, &client);

        if (socket_fd < 0) {
	    perror("Accept failed");
            exit(EXIT_FAILURE);
        }

	int pid = fork();
        if (pid == 0) {
            // Redirect STDIN to this connection, so it can take input from user
            dup2(socket_fd, STDIN_FILENO);

	    /* Uncomment the following if we want to send the output back to user.
	     * This is useful for remote attacks. 
            int output_fd = socket(AF_INET, SOCK_STREAM, 0);
            client.sin_port = htons(9091);
	    if (!connect(output_fd, (struct sockaddr *)&client, sizeof(struct sockaddr_in))){
               // If the connection is made, redirect the STDOUT to this connection
               dup2(output_fd, STDOUT_FILENO);
	    }
	    */ 

	    // Invoke the program 
	    fprintf(stderr, "Starting %s\n", PROGRAM);
            //execl(PROGRAM, PROGRAM, (char *)NULL);
	    // Using the following to pass an empty environment variable array
            //execle(PROGRAM, PROGRAM, (char *)NULL, NULL);
	    
	    // Using the following to pass a randomly generated environment varraible array.
	    // This is useful to slight randomize the stack's starting point.
            execle(PROGRAM, PROGRAM, (char *)NULL, generate_random_env(random_n));
        }
        else {
            close(socket_fd);
	}
    } 

    close(listen_fd);
}


int socket_bind(int port)
{
    int listen_fd;
    int opt = 1;
    struct sockaddr_in server;

    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
    {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    memset((char *) &server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr *) &server, sizeof(server)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(listen_fd, 3) < 0)
    {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    return listen_fd;
}

int server_accept(int listen_fd, struct sockaddr_in *client)
{
    int c = sizeof(struct sockaddr_in);

    int socket_fd = accept(listen_fd, (struct sockaddr *)client, (socklen_t *)&c);
    char *ipAddr = inet_ntoa(client->sin_addr);
    printf("Got a connection from %s\n", ipAddr);
    return socket_fd;
}

// Generate environment variables. The length of the environment affects 
// the stack location. This is used to add some randomness to the lab.
char **generate_random_env(int length)
{
    const char *name = "randomstring=";
    char **env;

    env = malloc(2*sizeof(char *));

    env[0] = (char *) malloc((length + strlen(name))*sizeof(char));
    strcpy(env[0], name);
    memset(env[0] + strlen(name), 'A', length -1);
    env[0][length + strlen(name) - 1] = 0;
    env[1] = 0;
    return env;
}
```

## Task 1: Crashing the Program

To crash the program, we can just type a bunch of `%s%s%s%s%s%s%s%s%s` as the format string. When `printf` uses this format string, it will take each address that `ap` points to as a pointer to a string. If any of these addresses are in kernelland, the program will crash.

## Task 2: Printing Out the Server Program’s Memory

### Stack Data

This one is easy. We can find the address of our input by putting in some "feature characters" like '@@@@' and a bunch of "%.8x" then inspect the output. Then input the format string in such a way that `ap` will move to the address of our interest and print out the values.

### Heap Data

We can first store the heap address (given in this lab) in the format string, and then use it as an address for printing out the "string" pointed by this address. This way we can find some secret message in the heap.

## Task 3: Modifying the Server Program’s Memory

### Change the value to a different value

We can first store the address of the value we want to overwrite and then put a bunch of "%.8x". Most importantly, we put a "%.n" to the end of the format string, and it will write to the address the number of bytes output so far. Note, we need to calculate the size of "gap" between the fmt pointer and the actual format string.

### Change the value to 0x5000

Similar to above, but here we need to have a larger `width` specifier to move the pointer to `0x5000`.

### Change the value to 0xAABBCCDD

The value is too large and would take too much time if we use `width` specifier. 
> The basic idea is to use %hn or %hhn, instead of %n, so we can modify a two-byte (or one-byte) memory space, instead of four bytes. 

## Task 4: Inject Malicious Code into the Server Program

The main idea is to inject shell code into the stack and then modify the return address and jump to the shell code. Note we can use a bunch of `nop` instructions (`nop sled`) to simplify our exploit.

To exploit the vulnerability on a remote server, we can inject code in such a way that would give us a reverse shell.


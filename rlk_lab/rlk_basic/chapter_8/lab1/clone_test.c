#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <sys/types.h>
#include <sys/wait.h>

int param = 0;

int thread_fn(void *data)
{
	int j;
	printf("starting child thread_fn, pid=%d\n", getpid());
	for (j = 0; j < 10; j++) {
		param = j + 1000;
		sleep(1);
		printf("child thread running: j=%d, param=%d secs\n", j,
		       param);
	}
	printf("child thread_fn exit\n");
	return 0;
}

int main(int argc, char **argv)
{
	int j, tid, pagesize, stacksize;
	void *stack;

	printf("starting parent process, pid=%d\n", getpid());

	pagesize = getpagesize();
	stacksize = 4 * pagesize;

	/* could probably just use malloc(), but this is safer */
	/* stack = (char *)memalign (pagesize, stacksize); */
	posix_memalign(&stack, pagesize, stacksize);

	printf("Setting a clone child thread with stacksize = %d....", stacksize);
	tid = clone(thread_fn, (char *)stack + stacksize, CLONE_VM | SIGCHLD, 0);
	printf(" with tid=%d\n", tid);
	if (tid < 0)
		exit(EXIT_FAILURE);

	/* could do a  wait (&status) here if required */
	for (j = 0; j < 6; j++) {
		param = j;
		sleep(1);
		printf("parent running: j=%d, param=%d secs\n", j,
		       param);
	}
	printf("parent killitself\n");
	/* We shouldn't free(stack) here since the child using it is still running */
	exit(EXIT_SUCCESS);
}


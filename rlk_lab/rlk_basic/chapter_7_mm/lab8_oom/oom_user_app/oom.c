#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define SIZE   (10*1024*1024)

static int alloc_mem(long int size)
{
	char *s;
	long i, pagesz = getpagesize();

	printf("thread(%lx), allocating %ld bytes.\n", (unsigned long)pthread_self(), size);

	s = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (s == MAP_FAILED)
		return errno;

	/* touch the memory */
	for (i = 0; i < size; i+= pagesz)
		s[i] = '\a';

	return 0;
}

static void *child_alloc_thread(void *args)
{
	int ret = 0;

	/* keep allocating until there is an error */
	while (!ret)
		alloc_mem(SIZE);

	exit(ret);
}

static void child_alloc(int threads)
{
	int i;
	pthread_t *th;
	int ret;

	th = malloc(sizeof(pthread_t) * threads);
	if (!th) {
		printf("malloc failed\n");
		goto out;
	}

	/* create threads */
	for (i = 0; i < threads; i++) {
		ret = pthread_create(&th[i], NULL, child_alloc_thread, NULL);
		if (ret) {
			printf("pthread_create error: %s\n", strerror(errno));
			/* keep going if thread other than first faild to spawn
			 * due to lack of resource.
			 */
			if (i == 0 || ret != EAGAIN)
				goto out;
		}
	}

	/* wait for one of threads to exit whole process */
	while(1)
		sleep(1);
out:
	exit(1);
}

int main(int argc, char **argv)
{
	int ncpus = -1;
	pid_t pid;
	int status, threads;
	int retcode;

	ncpus = sysconf(_SC_NPROCESSORS_ONLN);

	switch(pid = fork()) {
	case 0:
		threads = ncpus > 1 ? ncpus : 1;
		child_alloc(threads);
	default:
		break;
	}

	printf("expected victim is %d.\n", pid);
	waitpid(-1, &status, 0);

	if (WIFSIGNALED(status)) {
		printf("victim signalled: %d\n", WTERMSIG(status));
	}else if (WIFEXITED(status)) {
		retcode = WEXITSTATUS(status);
		printf("victim retcode: (%d) %s\n", retcode, strerror(retcode));
	}else{
		printf("victim unexpected ended\n");
	}

	return 0;
}

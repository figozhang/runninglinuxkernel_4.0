#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>

static int fd;

void my_signal_fun(int signum, siginfo_t *siginfo, void *act)
{
	int ret;
	char buf[64];

	if (signum == SIGIO) {
		if (siginfo->si_band & POLLIN) {
			printf("FIFO is not empty\n");
			if ((ret = read(fd, buf, sizeof(buf))) != -1) {
				buf[ret] = '\0';
				puts(buf);
			}
		}
		if (siginfo->si_band & POLLOUT)
			printf("FIFO is not full\n");
	}
}

int main(int argc, char *argv[])
{
	int ret;
	int flag;
	struct sigaction act, oldact;

	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGIO);
	act.sa_flags = SA_SIGINFO;
	act.sa_sigaction = my_signal_fun;
	if (sigaction(SIGIO, &act, &oldact) == -1)
		goto fail;

	fd = open("/dev/mydemo0", O_RDWR);
	if (fd < 0) 
		goto fail;

	/*设置异步IO所有权*/
	if (fcntl(fd, F_SETOWN, getpid()) == -1)
		goto fail;
	
	/*将当前进程PID设置为fd文件所对应驱动程序将要发送SIGIO,SIGUSR信号进程PID*/
	if (fcntl(fd, F_SETSIG, SIGIO) == -1)
		goto fail;
	
	/*获取文件flags*/
	if ((flag = fcntl(fd, F_GETFL)) == -1)
		goto fail;
	
	/*设置文件flags, 设置FASYNC,支持异步通知*/
	if (fcntl(fd, F_SETFL, flag | FASYNC) == -1)
		goto fail;

	while (1)
		sleep(1);

fail:
	perror("fasync test");
	exit(EXIT_FAILURE);
}

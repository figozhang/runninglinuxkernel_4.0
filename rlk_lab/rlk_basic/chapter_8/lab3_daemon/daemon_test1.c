#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/klog.h>

#define FALLBACK_KLOG_BUF_SHIFT 17  /* CONFIG_LOG_BUF_SHIFT in kernel */
#define FALLBACK_KLOG_BUF_LEN   (1 << FALLBACK_KLOG_BUF_SHIFT)

#define KLOG_CLOSE         0
#define KLOG_OPEN          1
#define KLOG_READ          2
#define KLOG_READ_ALL      3
#define KLOG_READ_CLEAR    4
#define KLOG_CLEAR         5
#define KLOG_CONSOLE_OFF   6
#define KLOG_CONSOLE_ON    7
#define KLOG_CONSOLE_LEVEL 8
#define KLOG_SIZE_UNREAD   9
#define KLOG_SIZE_BUFFER   10

/* we use 'Linux version' string instead of Oops in this lab */
//#define OOPS_LOG  "Oops" 
#define OOPS_LOG  "Linux version" 

int save_kernel_log(char *buffer)
{
	char path[128];
	time_t t;
	struct tm *tm;
	int fd;

	t = time(0);
	tm = localtime(&t);

	snprintf(path, 128, "/mnt/%d.%d.%d.%d.%d.%d.log", tm->tm_year+1900,
			tm->tm_mon+1, tm->tm_mday, tm->tm_hour,
			tm->tm_min, tm->tm_sec);
	printf("%s\n", path);
	
        fd = open(path, O_WRONLY|O_CREAT, 0644);
	if(fd == -1) {
		printf("open error\n");
		return -1;
	}
        write(fd, buffer, strlen(buffer));
        close(fd);

	return 0;
}

int check_kernel_log()
{
	char *buffer;
	char *p;
	ssize_t klog_size;
	int ret = -1;
	int size;

	printf("start kernel log\n");

	klog_size = klogctl(KLOG_SIZE_BUFFER, 0, 0);
	if (klog_size <= 0) {
		klog_size = FALLBACK_KLOG_BUF_LEN;
	}

	printf("kernel log size: %d\n", klog_size);

	buffer = malloc(klog_size + 1);
	if (!buffer)
		return -1;

	size = klogctl(KLOG_READ_ALL, buffer, klog_size);
	if (size < 0) {
		printf("klogctl read error\n");
		goto done;
	}

	buffer[size] = '\0';

	/* check if oops in klog */
	p = strstr(buffer,OOPS_LOG);
	if (p) {
		printf("we found '%s' on kernel log\n", OOPS_LOG);
		save_kernel_log(buffer);
		ret = 0;
	} 
done:
	free(buffer);
	return ret;
}

int main(void)
{
	if(daemon(0,0) == -1) {
		printf("daemon error");
		return 0;
	}
	
	while(1) {
		check_kernel_log();
		
		sleep(5);
	}
	
	return 0;
}

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define DEMO_DEV_NAME "/dev/my_demo_dev"

int main()
{
	char buffer[64];
	int fd;
	int ret;
	size_t len;
	char message[] = "Testing the virtual FIFO device";
	char *read_buffer;

	len = sizeof(message);

	fd = open(DEMO_DEV_NAME, O_RDWR);
	if (fd < 0) {
		printf("open device %s failded\n", DEMO_DEV_NAME);
		return -1;
	}

	/*1. write the message to device*/
	ret = write(fd, message, len);
	if (ret != len) {
		printf("canot write on device %d, ret=%d", fd, ret);
		return -1;
	}

	read_buffer = malloc(2*len);
	memset(read_buffer, 0, 2*len);

	ret = read(fd, read_buffer, 2*len);
	printf("read %d bytes\n", ret);
	printf("read buffer=%s\n", read_buffer);

	close(fd);

	return 0;
}

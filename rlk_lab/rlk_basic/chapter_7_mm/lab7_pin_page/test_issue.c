#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <malloc.h>

#define DEMO_DEV_NAME "/dev/my_demo_dev"

#define MYDEV_CMD_GET_BUFSIZE 1	/* defines our IOCTL cmd */

int main()
{
	int fd;
	int i;
	size_t len;
	char *read_buffer, *write_buffer;

	fd = open(DEMO_DEV_NAME, O_RDWR);
	if (fd < 0) {
		printf("open device %s failded\n", DEMO_DEV_NAME);
		return -1;
	}

	if (ioctl(fd, MYDEV_CMD_GET_BUFSIZE, &len) < 0) {
		printf("ioctl fail\n");
		goto open_fail;
	}

	printf("driver max buffer size=%d\n", len);

	read_buffer = malloc(len);
	if (!read_buffer)
		goto open_fail;

	write_buffer = malloc(len);
	if (!write_buffer)
		goto buffer_fail;

	/* modify the write buffer */
	for (i = 0; i < len; i++)
		*(write_buffer + i) = 0x55;

	if (write(fd, write_buffer, len) != len) {
		printf("write fail\n");
		goto rw_fail;
	}

	/* read the buffer back and compare with the mmap buffer*/
	if (read(fd, read_buffer, len) != len) {
		printf("read fail\n");
		goto rw_fail;
	}

	if (memcmp(write_buffer, read_buffer, len)) {
		printf("buffer compare fail\n");
		goto rw_fail;
	}

	printf("data modify and compare succussful\n");

	free(write_buffer);
	free(read_buffer);
	close(fd);

	return 0;

rw_fail:
	if (write_buffer)
		free(write_buffer);
buffer_fail:
	if (read_buffer)
		free(read_buffer);
open_fail:
	close(fd);
	return 0;
}

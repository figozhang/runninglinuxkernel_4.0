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
	char message[] = "Testing the virtual FIFO device";
	char *read_buffer, *mmap_buffer;

	len = sizeof(message);

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

	mmap_buffer = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (mmap_buffer == (char *)MAP_FAILED) {
		printf("mmap driver buffer fail\n");
		goto map_fail;
	}

	printf("mmap driver buffer succeeded: %p\n", mmap_buffer);

	/* modify the mmaped buffer */
	for (i = 0; i < len; i++)
		*(mmap_buffer + i) = (char)random();

	/* read the buffer back and compare with the mmap buffer*/
	if (read(fd, read_buffer, len) != len) {
		printf("read fail\n");
		goto read_fail;
	}

	if (memcmp(read_buffer, mmap_buffer, len)) {
		printf("buffer compare fail\n");
		goto read_fail;
	}

	printf("data modify and compare succussful\n");

	munmap(mmap_buffer, len);
	free(read_buffer);
	close(fd);

	return 0;

read_fail:
	munmap(mmap_buffer, len);
map_fail:
	free(read_buffer);
open_fail:
	close(fd);
	return -1;

}

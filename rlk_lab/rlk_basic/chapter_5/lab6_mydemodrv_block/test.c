#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define DEMO_DEV_NAME "/dev/my_demo_dev"

int main()
{
	int fd;
	int ret;
	size_t len;
	char message[80] = "Testing the virtual FIFO device";
	char *read_buffer;

	len = sizeof(message);
	
	read_buffer = malloc(2*len);
	memset(read_buffer, 0, 2*len);

	fd = open(DEMO_DEV_NAME, O_RDWR | O_NONBLOCK);
	if (fd < 0) {
		printf("open device %s failded\n", DEMO_DEV_NAME);
		return -1;
	}


	/*1: read it first*/
	ret = read(fd, read_buffer, 2*len);
	printf("read %d bytes\n", ret);
	printf("read buffer=%s\n", read_buffer);

	/*2. write the message to device*/
	ret = write(fd, message, len);
	if (ret != len)
		printf("have write %d bytes\n", ret);


	/*3. write again*/
	ret = write(fd, message, len);
	if (ret != len)
		printf("have write %d bytes\n", ret);

	ret = read(fd, read_buffer, 2*len);
	printf("read %d bytes\n", ret);
	printf("read buffer=%s\n", read_buffer);

	close(fd);

	return 0;
}

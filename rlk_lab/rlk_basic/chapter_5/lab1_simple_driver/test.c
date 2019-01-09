#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#define DEMO_DEV_NAME "/dev/demo_drv"

int main()
{
	char buffer[64];
	int fd;

	fd = open(DEMO_DEV_NAME, O_RDONLY);
	if (fd < 0) {
		printf("open device %s failded\n", DEMO_DEV_NAME);
		return -1;
	}

	read(fd, buffer, 64);
	close(fd);

	return 0;
}

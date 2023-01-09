/*
 * iouring has quite a bit of boilerplate, so liburing is provided to help with that.
 *
 * may need to install liburing-devel package on your linux
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <liburing.h>
#include <stdlib.h>

#define QUEUE_DEPTH 1
#define BLOCK_SZ 1024

struct file_info {
	off_t file_sz;
	struct iovec iovecs[];
};

int main() {
	printf("Hello, World!\n");
	return 0;
}

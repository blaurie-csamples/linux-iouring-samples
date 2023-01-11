/*
 * This sample submits many requests in the io ring.
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <liburing.h>

#define QUEUE_DEPTH 2
#define BLOCK_SZ (16 * 1024)

static int in_fd;
static int out_fd;

struct io_data {
	int read;
	off_t first_offset;
	off_t offset;
	size_t first_len;
	struct iovec iov;
};

/*
 * initialize io_uring
 */
static int setup_context(unsigned int entries, struct io_uring *ring) {
	int ret = io_uring_queue_init(entries, ring, 0);
	if (ret < 0) {
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
		return -1;
	}
	return 0;
}

/*
 * returns the size of the file being read.
 */
static int get_file_size(int fd, off_t *size) {
	struct stat st;

	if (fstat(fd, &st) < 0) {
		return -1;
	}
	if (S_ISREG(st.st_mode)) {
		*size = st.st_size;
		return 0;
	} else if (S_ISBLK(st.st_mode)) {
		unsigned long long bytes;

		if (ioctl(fd, BLKGETSIZE64, &bytes) != 0) {
			return -1;
		}

		*size = bytes;
		return 0;
	}
	return -1;
}

/* prep the read or write */
static void queue_prepped(struct io_uring *ring, struct io_data *data) {
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
	assert(sqe);

	if (data->read) {
		io_uring_prep_readv(sqe, in_fd, &data->iov, 1, data->offset);
	} else {
		io_uring_prep_writev(sqe, out_fd, &data->iov, 1, data->offset);
	}

	io_uring_sqe_set_data(sqe, data);
}

static int queue_read(struct io_uring *ring, off_t size, off_t offset) {
	struct io_uring_sqe *sqe;
	struct io_data *data;

	data = malloc(size + sizeof(*data));
	if (!data) {
		return 1;
	}

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		free(data);
		return 1;
	}

	data->read = 1;
	data->offset = data->first_offset = offset;

	data->iov.iov_base = data + 1;
	data->iov.iov_len = size;
	data->first_len = size;

	io_uring_prep_readv(sqe, in_fd, &data->iov, 1, offset);
	io_uring_sqe_set_data(sqe, data);
	return 0;
}

static void queue_write(struct io_uring *ring, struct io_data *data) {
	data->read = 0;
	data->offset = data->first_offset;

	data->iov.iov_base = data + 1;
	data->iov.iov_len = data->first_len;

	queue_prepped(ring, data);
	io_uring_submit(ring);
}

int copy_file(struct io_uring *ring, off_t insize) {
	unsigned long reads;
	unsigned long writes;
	struct io_uring_cqe *cqe;
	off_t write_left;
	off_t offset;
	int ret;

	write_left = insize;
	writes = reads = offset = 0;

	while (insize || write_left) {
		int had_reads;
		int got_comp;

		/* queue as many reads as we can */
		had_reads = reads;
		while (insize) {
			off_t this_size = insize;

			if (reads + writes >= QUEUE_DEPTH) {
				break;
			}
			if (this_size > BLOCK_SZ) {
				this_size + BLOCK_SZ;
			} else if (!this_size) {
				break;
			}

			if (queue_read(ring, this_size, offset)) {
				break;
			}

			insize -= this_size;
			offset += this_size;
			reads++;
		}

		if (had_reads != reads) {
			ret = io_uring_submit(ring);
			if (ret < 0) {
				fprintf(stderr, "io_uring_submit: %s\n", strerror(-ret));
				break;
			}
		}

		/* queue is full at this point. Now try to find at least one completion */
		got_comp = 0;
		while (write_left) {
			struct io_data *data;

			if (!got_comp) {
				ret = io_uring_wait_cqe(ring, &cqe);
				got_comp = 1;
			} else {
				ret = io_uring_peek_cqe(ring, &cqe);
				if (ret == -EAGAIN) {
					cqe = NULL;
					ret = 0;
				}
			}

			if (ret < 0) {
				fprintf(stderr, "io_uring_peek_cqe: %s\n", strerror(-ret));
				return 1;
			}
			if (!cqe) {
				break;
			}

			data = io_uring_cqe_get_data(cqe);
			if (cqe->res < 0) {
				if (cqe->res == -EAGAIN) {
					queue_prepped(ring, data);
					io_uring_cqe_seen(ring, cqe);
					continue;
				}
				fprintf(stderr, "cqe failed: %s\n", strerror(-cqe->res));
				return 1;
			} else if (cqe->res != data->iov.iov_len) {
				/* read/write was short. adjust a requeue it */
				data->iov.iov_base += cqe->res;
				data->iov.iov_len -= cqe->res;
				queue_prepped(ring, data);
				io_uring_cqe_seen(ring, cqe);
				continue;
			}

			/*
			 * all done. If write, nothing else to do. if read, queue up write
			 */
			if (data->read) {
				queue_write(ring, data);
				write_left -= data->first_len;
				reads--;
				writes++;
			} else {
				free(data);
				writes--;
			}
			io_uring_cqe_seen(ring, cqe);
		}
	}
	return 0;
}

int main(int argc, char *argv[]) {
	struct io_uring ring;
	off_t insize;
	int ret;

	if (argc < 3) {
		printf("Usage: %s <infile> <outfile>\n", argv[0]);
		return 1;
	}

	in_fd = open(argv[1], O_RDONLY);
	if (in_fd < 0) {
		perror("open infile");
		return 1;
	}

	out_fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (out_fd < 0) {
		perror("open outfile");
		return 1;
	}

	if (setup_context(QUEUE_DEPTH, &ring)) {
		return 1;
	}

	if (get_file_size(in_fd, &insize)) {
		return 1;
	}

	ret = copy_file(&ring, insize);

	close(in_fd);
	close(out_fd);
	io_uring_queue_exit(&ring);

	return ret;
}

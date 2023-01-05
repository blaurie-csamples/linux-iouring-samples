/**
 * an io ring instance has two queues:
 *  Submission Queue (SQ)
 *  Completion Queue (CQ)
 *  shared between the kernel and the application
 *  They are single producer single consumer and have a power of 2 size
 *
 *  The application creates one or more SQ Entries (SQE) and then updates the SQ Tail
 *  The kernel consumes the SQEs and updates the SQ Head
 *
 *  The Kernel creates CQ Entries (CQE) for one or more completed requests and updates the CQ Tail
 *  The application consumes the CQEs and updates the CQ Head.
 *
 *  Completion events can arrive in any order, but are always associated with specific SQEs
 *
 *  After submitting SQEs (can be read, writes, etc), the application calls io_uring_enter to
 *  inform the kernel about new submissions. There is also a mode where the kernel polls for entries
 *  on the SQ.
 *
 *  The CQE Struct:
 *      struct io_uring_cqe {
 *          __u64 user_data; //sqe->user_data submission passed back
 *          __s32 res; //result code for this event
 *          __u32 flags;
 *      }
 *
 *      The user_data is passed as is from the SQE to the CQE. Due to there being no guarantee that
 *      the SQE will process in order.
 *
 *  The SQE Struct
 *      struct io_uring_sqe {
 *          __u8 opcode;        // type of operation for this SQE (IORING_OP_READV ex)
 *          __u8 flags;         // IOSQE_ flags
 *          __u16 ioprio;       // ioprio for the request
 *          __s32 fd;           // file descriptor
 *          __u64 off;          // offset in to file;
 *          __u46 addr;         //pointer to buffer of iovecs
 *          __u32 len;          // buffer size of number of iovecs
 *          union {
 *              __kernel_rwf_t rw flags;
 *              __u32 fsync_flags;
 *              __u16 poll_events;
 *              __u32 sync_range_flags;
 *              __u32 msg_flags;
 *          };
 *          __u64 user_data;    // data passed back at completion time
 *          union {
 *              __u16 buf_index;    //index into fixed buffers if used
 *              __u64 __pad3[3];
 *          };
 *      }
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <linux/io_uring.h>

#define QUEUE_DEPTH 1
#define BLOCK_SZ 1024

/* x86 specific */
/*
 * Forces the compiler to not re-order memory accesses, even during optimization
 * __asm__ is a gcc extension of permitting assembly language statements to be nested in c code
 *          Use here is to specify compiler optimization may result is side effects
 * __volatile__ required to make sure the asm instruction itself is not reordered with
 *              any other volatile accesses
 *
 * memory instructs GCC that theres effects on global memory, not just local variables
 *        need to be taken in to account
 *
 * With io_uring we have a shared buffer across two contexts (user and kernel space)
 * which can run on different CPUs after a context switch. So we need to ensure from
 * userspace that before we read, previous writes are available.
 */
#define read_barrier() __asm__ __volatile__("":::"memory")
#define write_barrier() __asm__ __volatile__("":::"memory")

struct app_io_sub_queue_ring {
	unsigned *head;             /* unsigned is an alias for unsigned int */
	unsigned *tail;
	unsigned *ring_mask;
	unsigned *ring_entries;
	unsigned *flags;
	unsigned *array;
};

struct app_io_comp_queue_ring {
	unsigned *head;
	unsigned *tail;
	unsigned *ring_mask;
	unsigned *ring_entries;
	struct io_uring_cqe *cqes;
};

struct submitter {
	int ring_fd;
	struct app_io_sub_queue_ring sqr;
	struct io_uring_sqe *sqes;
	struct app_io_comp_queue_ring cqr;
};

struct file_info {
	off_t file_sz;
	struct iovec iovecs[];
};

/* roll your own syscalls while these are not part of the standard C libraries on linux */
int io_uring_setup(unsigned entries, struct io_uring_params *p) {
	return (int) syscall(__NR_io_uring_setup, entries, p);
}

int io_uring_enter(int ring_fd, unsigned to_submit, unsigned min_complete, unsigned flags) {
	return (int) syscall(__NR_io_uring_enter, ring_fd, to_submit, min_complete);
}

/*
 * Returns the size of the file whose open file descriptor is passed in.
 * Properly handles regular file and block devices as well. Pretty.
 * */
off_t get_file_size(int fd) {
	struct stat st;
	if (fstat(fd, &st) < 0) {
		perror("fstat");
		return -1;
	}
	if (S_ISBLK(st.st_mode)) {
		unsigned long long bytes;
		if (ioctl(fd, BLKGETSIZE64, &bytes) != 0) {
			perror("ioctl");
			return -1;
		}
		return bytes;
	} else if (S_ISREG(st.st_mode))
		return st.st_size;
	return -1;
}


/**
 * io_uring requires a lot of setup, but it's not all that bad. Do to all this bilerplate,
 * liburing was created.
 * This code will not use liburing for understanding purposes.
 */
int app_setup_uring(struct submitter *s) {
	struct app_io_sub_queue_ring *sring = &(s->sqr);
	struct app_io_comp_queue_ring *cring = &(s->cqr);
	struct io_uring_params p;
	void *sq_ptr, *cq_ptr;

	/*
	 * need to pass io_uring_params structure to the io_uring_setup()
	 * call zeroed out. We should set any flags here as well.
	 */
	memset(&p, 0, sizeof(p));
	s->ring_fd = io_uring_setup(QUEUE_DEPTH, &p);
	if (s->ring_fd < 0) {
		perror("io_uring_setup");
		return 1;
	}

	/*
	 * io_uring communication happens with 2 buffers shared between kernel and user space
	 * (this is the submission ring and completion ring)
	 * They can be mapped with mmap() call in recent kernels
	 * While completion queue is directly manipulated, the submission queue has an
	 * indirection array in between. That is mapped as well.
	 *
	 * if the IORING_FEAT_SINGLE_MMAP feature is set, then we can do away with the
	 * second mmap call to map the completion ring
	 */

	int sring_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
	int cring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);

	//because newer kernels map the sqr and cqr together, they should have the same size
	if (p.features & IORING_FEAT_SINGLE_MMAP) {
		if (cring_sz > sring_sz) {
			sring_sz = cring_sz;
		}
		cring_sz = sring_sz;
	}
	//newer kernels will map the submission and completion queue now
	sq_ptr = mmap(0, sring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, s->ring_fd, IORING_OFF_SQ_RING);
	if (sq_ptr == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	if (p.features & IORING_FEAT_SINGLE_MMAP) {
		cq_ptr = sq_ptr;
	} else {
		//in older kernels, we map the cq ring separately
		cq_ptr = mmap(0, cring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, s->ring_fd, IORING_OFF_CQ_RING);
		if (cq_ptr == MAP_FAILED) {
			perror(("cq mmap"));
			return 1;
		}
	}


	// map submission queue entries array
	s->sqes = mmap(0, p.sq_entries * sizeof(struct io_uring_sqe), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
				   s->ring_fd, IORING_OFF_SQES);
	if (s->sqes == MAP_FAILED) {
		perror("mmap array");
		return 1;
	}

	//saving useful fields in the submitter struct for easier reference later
	sring->head = sq_ptr + p.sq_off.head;
	sring->tail = sq_ptr + p.sq_off.tail;
	sring->ring_mask = sq_ptr + p.sq_off.ring_mask;
	sring->ring_entries = sq_ptr + p.sq_off.ring_entries;
	sring->flags = sq_ptr + p.sq_off.flags;
	sring->array = sq_ptr + p.sq_off.array;

	cring->head = cq_ptr + p.cq_off.head;
	cring->tail = cq_ptr + p.cq_off.tail;
	cring->ring_mask = cq_ptr + p.cq_off.ring_mask;
	cring->ring_mask = cq_ptr + p.cq_off.ring_entries;
	cring->cqes = cq_ptr + p.cq_off.cqes;

	return 0;
}

/*
 * output a string of characters of len length to the stdout. Buffered output used for efficiency since this is
 * character by character
 */
void output_to_console(char *buf, int len) {
	while (len--) {
		fputc(*buf++, stdout);
	}
}

/*
 * read completion events from the completion queue, get the data buffer that will have the file data and print it
 * to the console
 */
void read_from_cq(struct submitter *s) {
	struct file_info *fi;
	struct app_io_comp_queue_ring *cring = &(s->cqr);
	struct io_uring_cqe *cqe;
	unsigned head, reaped = 0;

	head = *(cring->head);

	do {
		read_barrier();

		if (head == *(cring->tail)) {
			break;
		}

		// get the entry
		cqe = &(cring->cqes[head & *(s->cqr.ring_mask)]);
		fi = (struct file_info*) cqe->user_data;
		if (cqe->res < 0) {
			fprintf(stderr, "Error: %s\n", strerror(abs(cqe->res)));
		}

		int blocks = (int) fi->file_sz / BLOCK_SZ;
		if (fi->file_sz % BLOCK_SZ) blocks++;

		for (int i = 0; i < blocks; i++) {
			output_to_console(fi->iovecs[i].iov_base, fi->iovecs[i].iov_len);
		}

		head++;
	} while (1);

	*cring->head = head;
	write_barrier();
}

/*
 * Submit to submission queue. Can submit many types of requests, but these will be readv requests.
 */
int submit_to_sq(char *file_path, struct submitter *s) {
	struct file_info *fi;

	int file_fd = open(file_path, O_RDONLY);
	if (file_fd < 0) {
		perror("open");
		return 1;
	}

	struct app_io_sub_queue_ring *sring = &(s->sqr);
	unsigned index = 0, current_block = 0, tail = 0, next_tail = 0;

	off_t file_sz = get_file_size(file_fd);
	if (file_sz < 0) {
		return 1;
	}

	off_t bytes_remaining = file_sz;
	int blocks = (int) file_sz / BLOCK_SZ;
	if (file_sz % BLOCK_SZ) blocks++;

	//fi = malloc(sizeof(*fi) + sizeof(struct iovec) * blocks);
	fi = malloc(sizeof(off_t) + sizeof(struct iovec) * blocks);
	if (!fi) {
		fprintf(stderr, "Unable to allocate memory\n");
		return 1;
	}
	fi->file_sz = file_sz;

	/*
	 * need to allocate an iovec struct for each block that needs to be read.
	 */
	while (bytes_remaining) {
		off_t bytes_to_read = bytes_remaining;
		if (bytes_to_read > BLOCK_SZ) {
			bytes_to_read = BLOCK_SZ;
		}

		fi->iovecs[current_block].iov_len = bytes_to_read;

		void *buf;
		if (posix_memalign(&buf, BLOCK_SZ, BLOCK_SZ)) {
			perror("posix_memalign");
			return 1;
		}
		fi->iovecs[current_block].iov_base = buf;

		current_block++;
		bytes_remaining -= bytes_to_read;
	}

	//add to the tail of the sqe ring buffer
	next_tail = tail = *sring->tail;
	next_tail++;
	read_barrier();
	index = tail & *s->sqr.ring_mask;
	struct io_uring_sqe *sqe = &s->sqes[index];
	sqe->fd = file_fd;
	sqe->flags = 0;
	sqe->opcode = IORING_OP_READV;
	sqe->addr = (unsigned long) fi->iovecs;
	sqe->len = blocks;
	sqe->off = 0;
	sqe->user_data = (unsigned long long) fi;
	sring->array[index] = index;
	tail = next_tail;

	//update the tail so the kernel can see the sqe
	if (*sring->tail != tail) {
		*sring->tail = tail;
		write_barrier();
	}

	/*
	 * now let the kernel know we have events submitted using the io_uring_enter() system call. Also pass along the
	 * IOURING_ENTER_GETEVENTS flag causing the io_uring_enter() call to wait until min_complete (3rd parameter)
	 * events complete.
	 */
	int ret = io_uring_enter(s->ring_fd, 1, 1, IORING_ENTER_GETEVENTS);
	if (ret < 0) {
		perror("io_uring_enter");
		return 1;
	}

	return 0;
}

//now main

int main() {
	printf("Hello, World!\n");
	return 0;
}

#include <stdio.h>

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
 */

int main() {
    printf("Hello, World!\n");
    return 0;
}

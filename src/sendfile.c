/*************************************************************************\
*                  Copyright (C) Michael Kerrisk, 2022.                   *
*                  Copyright (C) Ookiineko, 2022.                         *
*                                                                         *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/

/*
 * sendfile.c
 *
 * Implement sendfile() in terms of read(), write(), and lseek().
 * modified from https://man7.org/tlpi/code/online/dist/sockets/sendfile.c.html
 */

#include <sys/param.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/sendfile.h>

#ifdef __CYGWIN__

#define ERR             (-1)
#define BUFF_SIZE       8192

#ifdef _USE_SENDFILE
ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
    /* According to manpage, this is not currently supported by sendfile(). */
    int flags;
    if ((flags = fcntl(in_fd, F_GETFL)) == ERR)
        goto error;
    if (flags & O_APPEND) {
        errno = EINVAL;
        goto error;
    }

    /* According manpage:
     *     sendfile() will transfer at most 0x7ffff000 (2,147,479,552)
     *     bytes, returning the number of bytes actually transferred.  (This
     *     is true on both 32-bit and 64-bit systems.) */
    #define MAX_RW_COUNT            0x7ffff000
    if (count > MAX_RW_COUNT)
        count = MAX_RW_COUNT;

    /* in_fd must correspond to a regular file or block device. */
    struct stat in_stat;
    if (fstat(in_fd, &in_stat))
        goto error;
    mode_t in_mode = in_stat.st_mode;
    if (!S_ISREG(in_mode) && !S_ISBLK(in_mode)) {
        errno = EINVAL;
        goto error;
    }

    /* Save current file offset and set offset to value in '*offset' */
    off_t orig = -1;  // make compiler happy
    if (offset) {
        if ((orig = lseek(in_fd, 0, SEEK_CUR)) == ERR)
            goto error;
        if (in_stat.st_size < 0) {
            errno = EINVAL;
            goto error;
        }
        if (orig + count > (unsigned) in_stat.st_size) {
            errno = EOVERFLOW;
            goto error;
        }
        if (lseek(in_fd, *offset, SEEK_SET) == ERR)
            goto error;
    }

    /* if out_fd is seekable, check overflows as well. */
    struct stat out_stat;
    if (fstat(out_fd, &out_stat))
        goto error;
    mode_t out_mode = out_stat.st_size;
    if (S_ISREG(out_mode) || S_ISBLK(out_mode)) {
        off_t curr;
        if ((curr = lseek(out_fd, 0, SEEK_CUR)) == ERR)
            goto error;
        if (out_stat.st_size < 0) {
            errno = EINVAL;
            goto error;
        }
        if (curr + count > (unsigned) in_stat.st_size) {
            errno = EOVERFLOW;
            goto error;
        }
    }

    ssize_t total = 0, read_n, write_n;
    char buf[BUFF_SIZE];
    size_t amount;
    while (count) {
        amount = MIN(BUFF_SIZE, count);
        if ((read_n = read(in_fd, buf, amount)) == ERR)
            goto error;
        if (!read_n)
            break;                      /* EOF */
        if ((write_n = write(out_fd, buf, read_n)) == ERR)
            goto error;
        if (!write_n) {               /* Should never happen */
            fprintf(stderr, "linux_compat: sendfile(): write() should never == 0.");
            abort();
        }
        count -= write_n;
        total += write_n;
    }

    /* Return updated file offset in '*offset', and reset the file offset
       to the value it had when we were called. */
    if (offset && ((*offset = lseek(in_fd, 0, SEEK_CUR)) == ERR ||
                   lseek(in_fd, orig, SEEK_SET) == ERR))
        goto error;
    return total;
error:
    return ERR;
}
#else
ssize_t _sendfile(int __unused out_fd, int __unused in_fd, off_t __unused *offset, size_t __unused count) {
    errno = ENOSYS;
    return -1;
}
#endif

#endif

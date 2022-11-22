#ifdef __CYGWIN__

#ifndef _SYS_SENDFILE_H
#define _SYS_SENDFILE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>

#ifdef _USE_SENDFILE
ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
#else
ssize_t _sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SENDFILE_H */

#else
#include_next <sys/sendfile.h>
#endif

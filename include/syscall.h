#ifdef __CYGWIN__

#include <sys/syscall.h>

#else
#include_next <syscall.h>
#endif

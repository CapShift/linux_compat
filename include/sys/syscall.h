#ifdef __CYGWIN__

#ifndef _SYS_SYSCALL_H
#define _SYS_SYSCALL_H

#include <bits/syscall.h>

#endif

#else
#include_next <sys/syscall.h>
#endif

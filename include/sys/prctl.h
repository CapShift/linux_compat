#ifdef __CYGWIN__

#ifndef _SYS_PRCTL_H
#define _SYS_PRCTL_H    1

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* Values to pass as first argument to prctl() */

#define PR_SET_PDEATHSIG  1  /* Second arg is a signal */
#define PR_GET_PDEATHSIG  2  /* Second arg is a ptr to return the signal */

/* Get/set coredump state */
#define PR_GET_DUMPABLE   3
#define PR_SET_DUMPABLE   4

#define PR_SET_NAME    15               /* Set thread name */
#define PR_GET_NAME    16               /* Get thread name */

#ifdef _USE_PRCTL
int prctl(int option, ...);
#else
int _prctl(int option, ...);
#endif

#ifdef __cplusplus
}
#endif

#endif  /* _SYS_PRCTL_H */

#else
#include_next <sys/prctl.h>
#endif

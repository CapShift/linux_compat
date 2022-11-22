/*
 * prctl.c
 *
 * Operations on a process or thread.
 */

#include <stdarg.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/resource.h>
#include <dlfcn.h>
#ifdef __CYGWIN__
#include <sys/cygwin.h>
#endif
#include <pthread.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <sys/prctl.h>

#ifndef __linux__
/* stubs */
#define PR_GET_TIMING               13
#define PR_SET_TIMING               14
#define PR_TIMING_STATISTICAL       0

#define PR_GET_TSC                  25
#define PR_SET_TSC                  26
#define PR_TSC_ENABLE               1

#define PR_GET_TIMERSLACK           30

#define PR_MCE_KILL                 33
#define PR_MCE_KILL_CLEAR           0
#define PR_MCE_KILL_SET             1

#define PR_MCE_KILL_DEFAULT         2

#define PR_MCE_KILL_GET             34

#define PR_SET_MM                   35

#define PR_SET_CHILD_SUBREAPER      36
#define PR_GET_CHILD_SUBREAPER      37

#define PR_GET_NO_NEW_PRIVS         39

#define PR_SET_THP_DISABLE          41
#define PR_GET_THP_DISABLE          42

#define PR_GET_SPECULATION_CTRL     52
#define PR_SET_SPECULATION_CTRL     53
#define PR_SPEC_STORE_BYPASS        0
#define PR_SPEC_INDIRECT_BRANCH     1
#define PR_SPEC_ENABLE              (1UL << 1)
#define PR_SPEC_DISABLE             (1UL << 2)
#define PR_SPEC_FORCE_DISABLE       (1UL << 3)
#define PR_SPEC_DISABLE_NOEXEC      (1UL << 4)

#define PR_SET_IO_FLUSHER           57
#define PR_GET_IO_FLUSHER           58
#endif

/* for coredump settings */
#define SUID_DUMP_DISABLE       0
#define SUID_DUMP_USER          1

static int pdeathsig = 0;               /* current "pdeathsig" signal num */
static pid_t pdeathsig_helper = -1;     /* helper pid (for killing the helper while clearing) */

struct pdeathsig_t {
    bool flag;
    pthread_t tid;
};

static pid_t ppid = -1;
static struct pdeathsig_t *ptid = NULL;
static uid_t puid = -1;
static uid_t euid = -1;
static gid_t egid = -1;
static uid_t fsuid = -1;
static gid_t fsgid = -1;
static void (*handler_real)(int, siginfo_t *, void *) = NULL;

static pid_t (*fork_real)(void) = NULL;
static int (*sigaction_real)(int, const struct sigaction *, struct sigaction *) = NULL;

struct proc_status_t {
    union {
        uid_t user;
        gid_t group;
    } eid;
    union {
        uid_t user;
        gid_t group;
    } fsid;
};

static struct proc_status_t *read_proc_status(pid_t pid, const char *field) {
    if ((kill(pid, 0) == -1 && errno == ESRCH) || field == NULL)
        goto abort;
    size_t min = strlen(field);
    if (min < 1)
        goto abort;
    struct proc_status_t* ret = malloc(sizeof(struct proc_status_t));
    if (!ret)
        goto abort;
    char path[PATH_MAX], search[17];
    sprintf(path, "/proc/%u/status", pid);
    FILE *fp = fopen(path, "r");
    if (!fp)
        goto abort;
    ssize_t read;
    size_t len;
    char *line;
    strncpy(search, field, min + 1);
    strncat(search, ":\t%u\t%u\t%u\t%u", sizeof(search) - strlen(search) - 1);
    union {
        uid_t unused_uid;
        gid_t unused_gid;
    } unused;
    while ((read = getline(&line, &len, fp)) != -1) {
        if (read > 0 && len >= min && !strncmp(line, field, min)) {
            if (!sscanf(line, search, &unused, &ret->eid, &unused, &ret->fsid))
                goto abort;
            return ret;
        }
    }
abort:
    return NULL;
}

/* these 4 functions "should" never fail */
static uid_t getpeuid(pid_t _ppid) {
    struct proc_status_t *ptr = read_proc_status(_ppid, "Uid");
    assert(ptr);
    uid_t ret = ptr->eid.user;
    free(ptr);
    return ret;
}

static gid_t getpegid(pid_t _ppid) {
    struct proc_status_t *ptr = read_proc_status(_ppid, "Gid");
    assert(ptr);
    gid_t ret = ptr->eid.group;
    free(ptr);
    return ret;
}

static uid_t getfsuid(pid_t _pid) {
    struct proc_status_t *ptr = read_proc_status(_pid, "Uid");
    assert(ptr);
    uid_t ret = ptr->fsid.user;
    free(ptr);
    return ret;
}

static gid_t getfsgid(pid_t _pid) {
    struct proc_status_t *ptr = read_proc_status(_pid, "Gid");
    assert(ptr);
    gid_t ret = ptr->fsid.group;
    free(ptr);
    return ret;
}

static pid_t fork_wrap() {
    ppid = getpid();
    if (ptid)
        free(ptid);
    ptid = malloc(sizeof(struct pdeathsig_t));
    ptid->flag = true;
    ptid->tid = pthread_self();
    if (!ptid->tid) {
        perror("pthread_self()");
        abort();
    }
    puid = getuid();
    assert(fork_real);  /* constructor not working */
    pid_t pid = fork_real();
    if (pid == 0) {
        /* reset pdeathsig and helper pid on new process
         * NOTE: this does not affect execve() */
        pdeathsig = 0;
        pdeathsig_helper = -1;
    }
    return pid;
}

#ifdef __CYGWIN__
#define RTLD_NEXT   NULL  /* unchecked but this works */
#endif

void handler_wrap(int sig, siginfo_t *si, void *ucontext) {
    assert(handler_real);  /* should never happen */
    if (pdeathsig_helper != -1 && si->si_pid == pdeathsig_helper) {  /* filter the situation when we have helper currently,
                                                                      * and the signal is from the helper. */
        assert(ppid != -1 && puid != -1);  /* fork() hook not working?? */
        si->si_pid = ppid;
        si->si_uid = puid;
    }
    handler_real(sig, si, ucontext);  /* callback */
}

int sigaction_wrap(int signum, const struct sigaction *act, struct sigaction *oldact) {
    if (act != NULL && act->sa_flags & SA_SIGINFO  /* filter SA_SIGINFO */
        && act->sa_sigaction) {  /* hijack only when there is handler enabled */
        handler_real = act->sa_sigaction;  /* backup the original handler */
        ((struct sigaction *)act)->sa_sigaction = handler_wrap;  /* override the handler */
    }
    return sigaction_real(signum, act, oldact);
}

static void __unused init_hook() {
    fork_real = dlsym(RTLD_NEXT, "fork");
    sigaction_real = dlsym(RTLD_NEXT, "sigaction");
#ifdef __CYGWIN__
    cygwin_internal(CW_HOOK, "fork", fork_wrap);
    cygwin_internal(CW_HOOK, "sigaction", sigaction_wrap);
#endif
} __attribute__((constructor))

static void __unused cleanup() {
    if (ptid)
        free(ptid);
} __attribute__((destructor()))

#define NEXT_ARG() va_arg(argp, unsigned long)
#define NEXT_ARG2(type) (type) NEXT_ARG()
#define NEXT_ARG3(type, name) type name = NEXT_ARG2(type);
#define NEXT_ARG4(name) unsigned long name = NEXT_ARG();

#ifdef _USE_PRCTL
#define PRCTL_IGNORE()                          \
    NEXT_ARG4(unused)                           \
    NEXT_ARG4(unused2)                          \
    NEXT_ARG4(unused3)                          \
    NEXT_ARG4(unused4)                          \
    if (unused | unused2 | unused3 | unused4)   \
        goto error;
#else
#define PRCTL_IGNORE()          abort();
#endif

#define PTR_AS_RET(return_val)    \
    NEXT_ARG3(int *, ptr)         \
    if (!ptr)                     \
        goto error;               \
    *ptr = return_val;

#define PRCTL_STUB(unset)   \
    PRCTL_IGNORE()          \
    ret = unset;

#define QUIT_ERRNO(error_num)     \
    errno = error_num;            \
    ret = -1;                     \
    goto quit;

#ifdef _USE_PRCTL
#define STUB_BLOCK(block)   block
#else
#define STUB_BLOCK(block)   abort();
#endif

#define THRNAMELEN      16

#define PRCTL_UNSET     0

#ifndef __linux__
#ifdef _USE_PRCTL
int prctl(int option, ...) {
#else
int _prctl(int option, ...) {
#endif
    va_list argp;
    va_start(argp, option);
    int ret = 0;
    switch (option) {
        case PR_SET_PDEATHSIG:
        {
            NEXT_ARG3(int, signal)
            if (signal == 0) {  /* clear */
                if (pdeathsig_helper != -1 && kill(pdeathsig_helper, 0) == 0) {  /* kill the old helper if present */
                    if (kill(pdeathsig_helper, SIGTERM)) {
                        perror("kill() helper");
                        abort();
                    }
                    pdeathsig_helper = -1;
                }
            } else if (signal < 1 || signal > SIGRTMAX)  /* check if the signal num is valid */
                goto error;
            else {
                assert(ptid->flag && ptid->tid);  /* hook not working */
                if (pthread_kill(ptid->tid, 0)) {
                    switch (errno) {
                        case ESRCH:
                            break;  /* parent is already gone, no signal is going to be sent */
                        default:
                            goto error;
                    }
                } else {
                    euid = geteuid();
                    egid = getegid();
                    pid_t my_pid = getpid();
                    fsuid = getfsuid(my_pid);
                    fsgid = getfsgid(my_pid);
                    pid_t pid = fork();
                    if (pid < 0) {  /* fork() failed */
                        perror("fork() helper");
                        abort();
                    } else if (pid == 0) {  /* in the child process, should never return. */
                        struct timespec ts;
                        ts.tv_sec = 1;
                        ts.tv_nsec = 0;
                        int status = EXIT_FAILURE;
                        while (!(kill(ppid, 0) || pthread_kill(ptid->tid, 0)) &&
                               errno != ESRCH) {  /* wait until the parent process or "parent" thread exits */
                            pid_t original_child = getppid();
                            if (original_child == 1)  /* the child process is dead first, what? */
                                goto helper_quit;
                            else if (getpeuid(original_child) != euid || getpegid(original_child) != egid ||
                                getfsuid(original_child) != fsuid || getfsgid((original_child)) != fsgid)
                                goto helper_exit;  /* pdeathsig is reset on euid/gid or fsuid/gid changes,
                                                    * so we quit the helper here. */
                            nanosleep(&ts, NULL);  // HACK: poll
                        }
                        if (kill(getppid(), signal) == 0) {  /* send the specified signal to the child process */
helper_exit:
                            status = EXIT_SUCCESS;
                        }
helper_quit:
                        exit(status);  /* NO RETURN in helper */
                    }
                    pdeathsig_helper = pid;  /* record the pid of helper */
                    // immediately return in the child process
                }
            }
            pdeathsig = signal;
        }
            break;
        case PR_GET_PDEATHSIG:
        {
            NEXT_ARG3(int *, ptr)
            if (!ptr)
                goto error;
            else {
                pid_t my_pid = getpid();
                if (pdeathsig && (geteuid() != euid || getegid() != egid || getfsuid(my_pid) != fsuid
                    || getfsgid(my_pid) != fsgid)) {
                    /* reset on these changes */
                    pdeathsig = 0;
                    pdeathsig_helper = -1;  /* helper will detect this and end itself, so just set to -1 here */
                }
                *ptr = pdeathsig;
            }
        }
            break;
        case PR_SET_NAME:
        {
            NEXT_ARG3(const char *, name)
            if (!name)
                goto error;
            char safe_name[THRNAMELEN];  /* max thread name length */
            strncpy(safe_name, name, sizeof(safe_name));
            assert(!pthread_setname_np(pthread_self(), safe_name));
        }
            break;
        case PR_GET_NAME:
        {
            NEXT_ARG3(char *, buf)
            if (!buf || pthread_getname_np(pthread_self(), buf, THRNAMELEN))
                goto error;
        }
            break;
        case PR_GET_DUMPABLE:
        {
            struct rlimit limit;
            if (getrlimit(RLIMIT_CORE, &limit)) {
                perror("getrlimit()");
                abort();
            }
            ret = limit.rlim_cur == 0 ? SUID_DUMP_DISABLE : SUID_DUMP_USER;
        }
            break;
        case PR_SET_DUMPABLE:
        {
            NEXT_ARG4(dumpable);
            rlim_t soft;
            switch (dumpable) {
                case SUID_DUMP_DISABLE:
                    soft = 0;
                    break;
                case SUID_DUMP_USER:
                    soft = RLIM_INFINITY;
                    break;
                default:
                    goto error;
            }
            struct rlimit limit;
            limit.rlim_cur = soft;
            if (setrlimit(RLIMIT_CORE, &limit)) {
                perror("setrlimit()");
                abort();
            }
        }
            break;
        case PR_GET_TIMING:  /* stubs */
            STUB_BLOCK(
        {
            ret = PR_TIMING_STATISTICAL;
        }
            )
            break;
        case PR_SET_TIMING:
            STUB_BLOCK(
        {
            NEXT_ARG4(timing)
            if (timing != PR_TIMING_STATISTICAL)
                goto error;
        }
            )
            break;
        case PR_GET_TSC:  /* stubs */
            STUB_BLOCK(
        {
            PTR_AS_RET(PR_TSC_ENABLE)
        }
            )
            break;
        case PR_SET_TSC:
            STUB_BLOCK(
        {
            NEXT_ARG4(tsc)
            if (tsc != PR_TSC_ENABLE)
                goto error;
        }
            )
            break;
        case PR_GET_TIMERSLACK:  /* stub */
            STUB_BLOCK(
        {
            ret = PRCTL_UNSET;
        }
            )
            break;
        case PR_MCE_KILL:  /* stubs */
            STUB_BLOCK(
        {
            NEXT_ARG4(op)
            NEXT_ARG4(policy)
            NEXT_ARG4(unused)
            NEXT_ARG4(unused2)
            if (unused | unused2)  /* unused args must be set to zero */
                goto error;
            switch (op) {
                case PR_MCE_KILL_CLEAR:
                    if (policy != 0)  /* unused arg must be set to zero */
                        goto error;
                    break;
                case PR_MCE_KILL_SET:
                    if (policy != PR_MCE_KILL_DEFAULT)
                        goto error;
                    break;
                default:
                    goto error;
            }
        }
            )
            break;
        case PR_MCE_KILL_GET:
        {
            PRCTL_STUB(PR_MCE_KILL_DEFAULT)
        }
            break;
        case PR_SET_MM:  /* stub */
            STUB_BLOCK(
        {
            QUIT_ERRNO(EPERM)
        }
            )
        case PR_SET_CHILD_SUBREAPER:  /* stubs, no luck to impl this without modifying Cygwin src ig */
            STUB_BLOCK(
        {
            NEXT_ARG4(subreaper)
            if (subreaper)
                goto error;
        }
            )
            break;
        case PR_GET_CHILD_SUBREAPER:
            STUB_BLOCK(
        {
            PTR_AS_RET(PRCTL_UNSET)
        }
            )
            break;
        case PR_GET_NO_NEW_PRIVS:  /* stubs */
        {
            PRCTL_STUB(PRCTL_UNSET)
        }
            break;
        case PR_SET_THP_DISABLE:  /* stubs */
        {
            PRCTL_IGNORE()
        } __attribute__((fallthrough));
        case PR_GET_THP_DISABLE:
            STUB_BLOCK(
        {
            ret = PRCTL_UNSET;
        }
            )
            break;
        case PR_GET_SPECULATION_CTRL:  /* stubs */
            STUB_BLOCK(
        {
            NEXT_ARG4(spec)
            NEXT_ARG4(unused)
            NEXT_ARG4(unused2)
            NEXT_ARG4(unused3)
            if (unused | unused2 | unused3)
                goto error;
            if (spec != PR_SPEC_STORE_BYPASS) {
                errno = ENODEV;
                ret = -1;
                goto quit;
            } else
                goto error;
        }
            )
        case PR_SET_SPECULATION_CTRL:
            STUB_BLOCK(
        {
            NEXT_ARG4(spec)
            NEXT_ARG4(ctrl_val)
            NEXT_ARG4(unused)
            NEXT_ARG4(unused2)
            if (unused | unused2)
                goto error;
            switch (spec) {
                case PR_SPEC_STORE_BYPASS:
                case PR_SPEC_INDIRECT_BRANCH:
                    switch (ctrl_val) {
                        case PR_SPEC_ENABLE:
                        case PR_SPEC_DISABLE:
                        case PR_SPEC_FORCE_DISABLE:
                        case PR_SPEC_DISABLE_NOEXEC:
                            goto error;
                        default:
                            QUIT_ERRNO(ERANGE)
                    }
                default:
                    QUIT_ERRNO(ENODEV)
            }
        }
            )
        case PR_SET_IO_FLUSHER:  /* stubs */
        case PR_GET_IO_FLUSHER:
            STUB_BLOCK(
        {
            QUIT_ERRNO(EPERM)
        }
            )
        default:
            goto error;
    }
quit:
    va_end(argp);
    return ret;
error:
    QUIT_ERRNO(EINVAL)
}
#endif

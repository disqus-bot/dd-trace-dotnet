#define _GNU_SOURCE
#include <dlfcn.h>
#include <linux/aio_abi.h>
#include <poll.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/select.h>
#include <sys/sem.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define SET_AS_ENTERED(B_) functions_entered_counters = (functions_entered_counters & ~(1 << B_)) | (1 << B_)
#define SET_AS_EXITED(B_) functions_entered_counters = (functions_entered_counters & ~(1 << B_))

__attribute__((visibility("hidden"))) __thread unsigned long functions_entered_counters;

__attribute__((visibility("hidden")))
unsigned long __dd_inside_io_wrapped_functions()
{
    return functions_entered_counters;
}

#define END(...) END_(__VA_ARGS__)
// cppcheck-suppress preprocessorErrorDirective
#define END_(...) __VA_ARGS__##_END

#define PARAMS_LOOP_0(type_, name_) PARAMS_LOOP_BODY(type_, name_) PARAMS_LOOP_A
#define PARAMS_LOOP_A(type_, name_) , PARAMS_LOOP_BODY(type_, name_) PARAMS_LOOP_B
#define PARAMS_LOOP_B(type_, name_) , PARAMS_LOOP_BODY(type_, name_) PARAMS_LOOP_A
#define PARAMS_LOOP_0_END
#define PARAMS_LOOP_A_END
#define PARAMS_LOOP_B_END
#define PARAMS_LOOP_BODY(type_, name_) type_ name_

#define VAR_LOOP_0(type_, name_) name_ VAR_LOOP_A
#define VAR_LOOP_A(type_, name_) , name_ VAR_LOOP_B
#define VAR_LOOP_B(type_, name_) , name_ VAR_LOOP_A
#define VAR_LOOP_0_END
#define VAR_LOOP_A_END
#define VAR_LOOP_B_END

#define PROTECT_CALL(stmt)                                  \
    int barrier_acquired = 0;                               \
    if (__dd_acquire_release_barrier != NULL)               \
        barrier_acquired = __dd_acquire_release_barrier(1); \
    stmt;                                                   \
    if (barrier_acquired != 0)                              \
        __dd_acquire_release_barrier(0);

#define WRAPPED_FUNCTION(bit_offset, return_type, name, parameters)              \
    static return_type (*__real_##name)(END(PARAMS_LOOP_0 parameters)) = NULL;   \
                                                                                 \
    return_type name(END(PARAMS_LOOP_0 parameters))                              \
    {                                                                            \
        if (__real_##name == NULL)                                               \
        {                                                                        \
            __real_##name = dlsym(RTLD_NEXT, #name);                             \
        }                                                                        \
                                                                                 \
        PROTECT_CALL(return_type rc = __real_##name(END(VAR_LOOP_0 parameters))) \
                                                                                 \
        return rc;                                                               \
    }

#ifdef __GLIBC__
#define DD_CONST
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 21
#undef DD_CONST
#define DD_CONST const
#endif
#endif

// make it volatile to prevent optimization
int (*volatile __dd_acquire_release_barrier)(int) = NULL;

WRAPPED_FUNCTION(0, int, accept, (int, sockfd)(struct sockaddr*, addr)(socklen_t*, addrlen))
WRAPPED_FUNCTION(1, int, accept4, (int, sockfd)(struct sockaddr*, addr)(socklen_t*, addrlen)(int, flags))
WRAPPED_FUNCTION(2, ssize_t, recv, (int, sockfd)(void*, buf)(size_t, len)(int, flags))
WRAPPED_FUNCTION(3, ssize_t, recvfrom, (int, sockfd)(void*, buf)(size_t, len)(int, flags)(struct sockaddr*, src_addr)(socklen_t*, addrlen))
WRAPPED_FUNCTION(4, ssize_t, recvmsg, (int, sockfd)(struct msghdr*, msg)(int, flags))
#ifdef DD_ALPINE
WRAPPED_FUNCTION(5, int, recvmmsg, (int, sockfd)(struct mmsghdr*, msgvec)(unsigned int, vlen)(unsigned int, flags)(struct timespec*, timeout))
#else
WRAPPED_FUNCTION(5, int, recvmmsg, (int, sockfd)(struct mmsghdr*, msgvec)(unsigned int, vlen)(int, flags)(DD_CONST struct timespec*, timeout))
#endif
WRAPPED_FUNCTION(6, int, connect, (int, sockfd)(const struct sockaddr*, addr)(socklen_t, addrlen))
WRAPPED_FUNCTION(7, ssize_t, send, (int, sockfd)(const void*, buf)(size_t, len)(int, flags))
WRAPPED_FUNCTION(8, ssize_t, sendto, (int, sockfd)(const void*, buf)(size_t, len)(int, flags)(const struct sockaddr*, dest_addr)(socklen_t, addrlen))
WRAPPED_FUNCTION(9, ssize_t, sendmsg, (int, sockfd)(const struct msghdr*, msg)(int, flags))
WRAPPED_FUNCTION(10, int, pause, (void, ))
WRAPPED_FUNCTION(11, int, sigsuspend, (const sigset_t*, mask))
WRAPPED_FUNCTION(12, int, sigwaitinfo, (const sigset_t*, set)(siginfo_t*, info))
WRAPPED_FUNCTION(13, int, sigtimedwait, (const sigset_t*, set)(siginfo_t*, info)(const struct timespec*, timeout))
WRAPPED_FUNCTION(14, int, epoll_wait, (int, epfd)(struct epoll_event*, events)(int, maxevents)(int, timeout))
WRAPPED_FUNCTION(15, int, epoll_pwait, (int, epfd)(struct epoll_event*, events)(int, maxevents)(int, timeout)(const sigset_t*, sigmask))
WRAPPED_FUNCTION(16, int, poll, (struct pollfd*, fds)(nfds_t, nfds)(int, timeout))
WRAPPED_FUNCTION(17, int, ppoll, (struct pollfd*, fds)(nfds_t, nfds)(const struct timespec*, tmo_p)(const sigset_t*, sigmask))
WRAPPED_FUNCTION(18, int, select, (int, nfds)(fd_set*, readfds)(fd_set*, writefds)(fd_set*, exceptfds)(struct timeval*, timeout))
WRAPPED_FUNCTION(19, int, pselect, (int, nfds)(fd_set*, readfds)(fd_set*, writefds)(fd_set*, exceptfds)(const struct timespec*, timeout)(const sigset_t*, sigmask))
WRAPPED_FUNCTION(20, int, msgsnd, (int, msqid)(const void*, msgp)(size_t, msgsz)(int, msgflg))
WRAPPED_FUNCTION(21, ssize_t, msgrcv, (int, msqid)(void*, msgp)(size_t, msgsz)(long, msgtyp)(int, msgflg))
WRAPPED_FUNCTION(22, int, semop, (int, semid)(struct sembuf*, sops)(size_t, nsops))
WRAPPED_FUNCTION(23, int, semtimedop, (int, semid)(struct sembuf*, sops)(size_t, nsops)(const struct timespec*, timeout))
WRAPPED_FUNCTION(24, int, clock_nanosleep, (clockid_t, clockid)(int, flags)(const struct timespec*, request)(struct timespec*, remain))
WRAPPED_FUNCTION(25, int, nanosleep, (const struct timespec*, req)(struct timespec*, rem))
WRAPPED_FUNCTION(26, int, usleep, (useconds_t, usec))
WRAPPED_FUNCTION(27, int, io_getevents, (aio_context_t, ctx_id)(long, min_nr)(long, nr)(struct io_event*, events)(struct timespec*, timeout))
// BEWARE when adding a new function, functions_entered_counters is 32-bit integer. So if you have add more than 32 functions, do not forget to change
// the type of functions_entered_counters into unsigned long long (64-bit integer)

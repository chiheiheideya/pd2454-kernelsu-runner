#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>

static long read_num(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char buf[64] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    return atol(buf);
}

static void slab_snap(const char *tag) {
    long obj = read_num("/sys/kernel/slab/posix_timers_cache/objects");
    long sl  = read_num("/sys/kernel/slab/posix_timers_cache/slabs");
    long pa  = read_num("/sys/kernel/slab/posix_timers_cache/partial");
    long cs  = read_num("/sys/kernel/slab/posix_timers_cache/cpu_slabs");
    printf("[slab] %s objects=%ld slabs=%ld partial=%ld cpu_slabs=%ld\n", tag, obj, sl, pa, cs);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[env] uid=%d euid=%d pid=%d\n", getuid(), geteuid(), getpid());
    printf("[env] enforce=%ld\n", read_num("/sys/fs/selinux/enforce"));
    printf("[env] kernelslab_readable=%ld\n", read_num("/sys/kernel/slab/posix_timers_cache/objects"));

    /* io_setup: aarch64 __NR_io_setup = 0 */
    void *ctx = NULL;
    errno = 0;
    long ret = syscall(0, 4, &ctx);
    printf("[io_setup] ret=%ld errno=%d ctx=%p\n", ret, errno, ctx);
    if (ret == 0) syscall(1, ctx); /* io_destroy */

    slab_snap("baseline");

    #define N 992
    timer_t *ts = calloc(N, sizeof(timer_t));
    int made = 0;
    for (int i = 0; i < N; i++) {
        struct sigevent sev;
        memset(&sev, 0, sizeof(sev));
        sev.sigev_notify = SIGEV_NONE;
        if (timer_create(CLOCK_PROCESS_CPUTIME_ID, &sev, &ts[i]) != 0) {
            printf("[timer] create fail at i=%d errno=%d\n", i, errno);
            break;
        }
        made++;
    }
    printf("[timer] made=%d\n", made);
    slab_snap("after_create");

    int step = 0;
    for (int b = 0; b < made; b += 31) {
        int end = b + 31 < made ? b + 31 : made;
        for (int i = b; i < end; i++) timer_delete(ts[i]);
        step++;
        if (step % 4 == 0 || end == made) {
            char tag[48];
            snprintf(tag, sizeof(tag), "release_%d", step);
            slab_snap(tag);
        }
    }
    slab_snap("after_release_all");
    printf("[done]\n");
    return 0;
}

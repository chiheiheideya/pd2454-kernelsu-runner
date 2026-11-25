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

/* /proc/slabinfo: posix_timers_cache active_objs num_objs objsize objperslab pagesperslab : ... : slabdata active_slabs num_slabs */
static void slab_snap(const char *tag) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) { printf("[slabinfo] %s open_fail\n", tag); return; }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "posix_timers_cache", 18) == 0) {
            char name[64];
            unsigned long aobj = 0, nobj = 0, osz = 0, ops = 0, pps = 0, asl = 0, nsl = 0;
            int n = sscanf(line, "%63s %lu %lu %lu %lu %lu : %*s %*u %*u %*u : %*s %lu %lu",
                           name, &aobj, &nobj, &osz, &ops, &pps, &asl, &nsl);
            (void)n;
            printf("[slabinfo] %s active_objs=%lu num_objs=%lu objperslab=%lu active_slabs=%lu num_slabs=%lu\n",
                   tag, aobj, nobj, ops, asl, nsl);
            fclose(f);
            return;
        }
    }
    fclose(f);
    printf("[slabinfo] %s no_entry\n", tag);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[env] uid=%d euid=%d pid=%d enforce=%ld\n", getuid(), geteuid(), getpid(), read_num("/sys/fs/selinux/enforce"));

    void *ctx = NULL;
    errno = 0;
    long ret = syscall(0, 4, &ctx);
    printf("[io_setup] ret=%ld errno=%d ctx=%p\n", ret, errno, ctx);
    if (ret == 0) {
        unsigned char *p = (unsigned char *)ctx;
        printf("[aio] read first bytes=%02x %02x %02x %02x (readonly check)\n", p[0], p[1], p[2], p[3]);
    }

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
        if (step % 2 == 0 || end == made) {
            char tag[48];
            snprintf(tag, sizeof(tag), "release_%d", step);
            slab_snap(tag);
        }
    }
    slab_snap("after_release_all");

    if (ret == 0) { syscall(1, ctx); printf("[aio] destroyed\n"); }
    printf("[done]\n");
    return 0;
}

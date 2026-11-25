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

static void slab_snap(const char *tag) {
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) { printf("[slabinfo] %s open_fail\n", tag); return; }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "posix_timers_cache", 18) == 0) {
            char name[64];
            unsigned long aobj = 0, nobj = 0, osz = 0, ops = 0, pps = 0, asl = 0, nsl = 0;
            sscanf(line, "%63s %lu %lu %lu %lu %lu : %*s %*u %*u %*u : %*s %lu %lu",
                   name, &aobj, &nobj, &osz, &ops, &pps, &asl, &nsl);
            printf("[slabinfo] %s active=%lu num=%lu asl=%lu nsl=%lu\n", tag, aobj, nobj, asl, nsl);
            fclose(f);
            return;
        }
    }
    fclose(f);
    printf("[slabinfo] %s no_entry\n", tag);
}

static long read_num(const char *p) {
    FILE *f = fopen(p, "r");
    long v = -1;
    if (!f) return -1;
    if (fscanf(f, "%ld", &v) != 1) v = -1;
    fclose(f);
    return v;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[env] uid=%d euid=%d aio_max_nr=%ld\n", getuid(), geteuid(), read_num("/proc/sys/fs/aio-max-nr"));

    /* io_setup errno 分类 */
    void *ctx = NULL;
    errno = 0;
    long ret = syscall(0, 4, &ctx);
    printf("[io_setup] ret=%ld errno=%d ctx=%p\n", ret, errno, ctx);
    if (ret == 0) syscall(1, ctx);

    slab_snap("baseline");

    #define N 620
    timer_t *ts = calloc(N, sizeof(timer_t));
    int made = 0;
    for (int i = 0; i < N; i++) {
        struct sigevent sev;
        memset(&sev, 0, sizeof(sev));
        sev.sigev_notify = SIGEV_NONE;
        if (timer_create(CLOCK_PROCESS_CPUTIME_ID, &sev, &ts[i]) != 0) {
            printf("[timer] create fail i=%d errno=%d\n", i, errno);
            break;
        }
        made++;
    }
    printf("[timer] made=%d\n", made);
    slab_snap("after_create");

    int ok = 0, fail = 0;
    for (int i = 0; i < made; i++) {
        if (timer_delete(ts[i]) == 0) ok++;
        else fail++;
    }
    printf("[delete] ok=%d fail=%d\n", ok, fail);
    slab_snap("just_after_delete");

    /* 等 RCU 回收后看 slab 是否被丢弃 */
    sleep(3);
    slab_snap("after_rcu_wait3s");
    printf("[done]\n");
    return 0;
}

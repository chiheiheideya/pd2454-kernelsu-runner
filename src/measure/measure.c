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
            printf("[slabinfo] %s active_objs=%lu num_objs=%lu active_slabs=%lu num_slabs=%lu\n",
                   tag, aobj, nobj, asl, nsl);
            fclose(f);
            return;
        }
    }
    fclose(f);
    printf("[slabinfo] %s no_entry\n", tag);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[env] uid=%d euid=%d\n", getuid(), geteuid());
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

    int ok = 0, fail = 0, firsterr = 0;
    for (int i = 0; i < made; i++) {
        if (timer_delete(ts[i]) == 0) ok++;
        else { fail++; if (!firsterr) firsterr = errno; }
        if ((i + 1) % 31 == 0) {
            char tag[48];
            snprintf(tag, sizeof(tag), "del_%d", i + 1);
            slab_snap(tag);
        }
    }
    printf("[delete] ok=%d fail=%d firsterrno=%d\n", ok, fail, firsterr);
    slab_snap("after_delete_all");
    printf("[done]\n");
    return 0;
}

/*
 * vm_spoof.c — LD_PRELOAD shim that lies to a sample trying to fingerprint
 * the analysis environment. Hides hypervisor flags, DMI strings and VM env vars.
 *
 * Compiled inside the sandbox image: gcc -shared -fPIC -O2 -o vm_spoof.so vm_spoof.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

static FILE *(*real_fopen)(const char *, const char *) = NULL;
static char *(*real_fgets)(char *, int, FILE *) = NULL;
static char *(*real_getenv)(const char *) = NULL;

static int is_interesting_path(const char *path) {
    if (!path) return 0;
    if (strstr(path, "cpuinfo")) return 1;
    if (strstr(path, "dmi/id/product_name")) return 1;
    if (strstr(path, "dmi/id/sys_vendor")) return 1;
    if (strstr(path, "dmi/id/board_vendor")) return 1;
    if (strstr(path, "/scsi/")) return 1;
    if (strstr(path, "/ide/")) return 1;
    return 0;
}

FILE *fopen(const char *path, const char *mode) {
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");
    if (is_interesting_path(path)) {
        FILE *fp = tmpfile();
        if (strstr(path, "cpuinfo")) {
            fputs("processor\t: 0\n"
                  "vendor_id\t: GenuineIntel\n"
                  "model name\t: Intel(R) Xeon(R) Gold 6226R CPU @ 2.90GHz\n"
                  "cpu family\t: 6\n"
                  "model\t\t: 79\n"
                  "stepping\t: 1\n"
                  "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov\n"
                  "bogomips\t: 5800.00\n", fp);
        } else {
            fputs("Dell Inc. PowerEdge R640\n", fp);
        }
        rewind(fp);
        return fp;
    }
    return real_fopen(path, mode);
}

FILE *fopen64(const char *path, const char *mode) {
    return fopen(path, mode);
}

char *fgets(char *s, int size, FILE *stream) {
    if (!real_fgets) real_fgets = dlsym(RTLD_NEXT, "fgets");
    return real_fgets(s, size, stream);
}

char *getenv(const char *name) {
    if (!real_getenv) real_getenv = dlsym(RTLD_NEXT, "getenv");
    if (name && (strstr(name, "VMWARE") || strstr(name, "VBOX") ||
                 strstr(name, "VIRTUAL") || strstr(name, "HYPERVISOR"))) {
        return NULL;
    }
    return real_getenv(name);
}

